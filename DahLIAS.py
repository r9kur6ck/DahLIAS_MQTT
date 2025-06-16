import time
import json
import uuid
import hashlib
from threading import Thread, Event

import paho.mqtt.client as mqtt
from ecdsa import SECP256k1, VerifyingKey, SigningKey
from ecdsa.util import string_to_number
from ecdsa.ellipticcurve import Point

# --- グローバル設定 ---
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
CURVE = SECP256k1
G = CURVE.generator

# --- ヘルパー関数 ---
def point_to_hex(point):
    affine_point = point if isinstance(point, Point) else point.to_affine()
    vk = VerifyingKey.from_public_point(affine_point, curve=CURVE)
    return vk.to_string("compressed").hex()

def hex_to_point(hex_str):
    vk = VerifyingKey.from_string(bytes.fromhex(hex_str), curve=CURVE)
    return vk.pubkey.point

def int_to_hex(n):
    return hex(n)

def hex_to_int(hex_str):
    return int(hex_str, 16)

def deterministic_hash(data):
    encoded_data = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(encoded_data).digest()

# --- 署名者クラス (IoTデバイス) ---
class Signer:
    def __init__(self, signer_id, message):
        self.signer_id = signer_id
        self.message = message
        self.sk = SigningKey.generate(curve=CURVE)
        self.pk = self.sk.verifying_key
        self.pk_hex = self.pk.to_string("compressed").hex()
        self.state = {}
        self.session_id = None
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1, client_id=f"signer-{self.signer_id}-{uuid.uuid4()}")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.connected_event = Event()

    def connect(self):
        self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
        self.client.loop_start()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print(f"[Signer {self.signer_id}] MQTTブローカーに接続しました。")
            self.client.subscribe("dahlias/session/start", qos=1)
            self.connected_event.set()
        else:
            print(f"[Signer {self.signer_id}] 接続失敗: {rc}")

    def _on_message(self, client, userdata, msg):
        try:
            data = json.loads(msg.payload.decode())
            session_id = data.get("session_id")
            msg_type = data.get("type")

            if msg.topic == "dahlias/session/start" and msg_type == "session_start":
                if self.session_id is not None: return
                print(f"[Signer {self.signer_id}] 署名セッション開始 (ID: {session_id})")
                self.session_id = session_id
                self.client.subscribe(f"dahlias/{session_id}/coordinator/to/signers")
                Thread(target=self._round1_publish_nonces).start()
            
            elif msg.topic == f"dahlias/{self.session_id}/coordinator/to/signers" and msg_type == "round2_start_ctx":
                print(f"[Signer {self.signer_id}] ラウンド2開始: ctxを受信")
                Thread(target=self._round2_handle_ctx, args=(data["payload"],)).start()

        except (json.JSONDecodeError, KeyError) as e:
            # retainされた空メッセージは無視
            if not msg.payload:
                return
            print(f"[Signer {self.signer_id}] 不正なメッセージを受信: {e} - {msg.payload.decode()}")

    def _round1_publish_nonces(self):
        r1 = SigningKey.generate(curve=CURVE).privkey.secret_multiplier
        r2 = SigningKey.generate(curve=CURVE).privkey.secret_multiplier
        
        R1_point = r1 * G
        R2_point = r2 * G

        self.state[self.session_id] = {'r1': r1, 'r2': r2, 'R2_hex': point_to_hex(R2_point)}
        
        payload = { "signer_id": self.signer_id, "pk_hex": self.pk_hex, "message": self.message, "R1_hex": point_to_hex(R1_point), "R2_hex": point_to_hex(R2_point) }
        msg = { "session_id": self.session_id, "type": "round1_output", "payload": payload }
        topic = f"dahlias/{self.session_id}/signers/to/coordinator"
        self.client.publish(topic, json.dumps(msg))
        print(f"[Signer {self.signer_id}] ラウンド1: 公開ナンスをPublishしました。")

    def _round2_handle_ctx(self, ctx):
        L_tuples = ctx['L_tuples']
        my_state = self.state[self.session_id]
        
        found_count = 0
        is_valid = False
        for entry in L_tuples:
            if entry['R2_hex'] == my_state['R2_hex']:
                found_count += 1
                if entry['pk_hex'] == self.pk_hex and entry['message'] == self.message:
                    is_valid = True
                else:
                    is_valid = False; break
        
        if found_count != 1 or not is_valid:
            print(f"[Signer {self.signer_id}] ctxの検証に失敗しました！プロトコルを中断します。")
            return
        
        print(f"[Signer {self.signer_id}] ctxの検証に成功しました。")

        R1_agg_point = hex_to_point(ctx['R1_agg_hex'])
        R2_agg_point = hex_to_point(ctx['R2_agg_hex'])

        b_hash_input = {k: ctx[k] for k in sorted(ctx)}
        b = string_to_number(deterministic_hash(b_hash_input))
        
        R_point = R1_agg_point + b * R2_agg_point
        
        L = [(item['pk_hex'], item['message']) for item in L_tuples]
        
        c_hash_input = {'L': L, 'R_hex': point_to_hex(R_point), 'pk_hex': self.pk_hex, 'message': self.message}
        c = string_to_number(deterministic_hash(c_hash_input))

        r_effective = (my_state['r1'] + b * my_state['r2']) % G.order()
        s_i = (r_effective + c * self.sk.privkey.secret_multiplier) % G.order()

        payload = { "signer_id": self.signer_id, "s_i_hex": int_to_hex(s_i) }
        msg = { "session_id": self.session_id, "type": "round2_output", "payload": payload }
        topic = f"dahlias/{self.session_id}/signers/to/coordinator"
        self.client.publish(topic, json.dumps(msg))
        print(f"[Signer {self.signer_id}] ラウンド2: 部分署名をPublishしました。")

# --- コーディネータークラス ---
class Coordinator:
    def __init__(self, num_signers):
        self.num_signers = num_signers
        self.session_id = str(uuid.uuid4())
        self.session_data = { "round1_inputs": {}, "round2_inputs": {}, "ctx": None, "final_R_point": None }
        self.verification_complete = Event()
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1, client_id=f"coordinator-{self.session_id}")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.connected_event = Event()

    def connect(self):
        self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
        self.client.loop_start()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print(f"[Coordinator] MQTTブローカーに接続しました。")
            self.client.subscribe(f"dahlias/{self.session_id}/signers/to/coordinator")
            self.connected_event.set()
        else:
            print(f"[Coordinator] 接続失敗: {rc}")

    def _on_message(self, client, userdata, msg):
        thread = Thread(target=self._process_message_thread, args=(msg,))
        thread.start()

    def _process_message_thread(self, msg):
        try:
            data = json.loads(msg.payload.decode())
            session_id = data.get("session_id")
            if session_id != self.session_id: return

            msg_type = data.get("type")
            payload = data.get("payload")
            signer_id = payload.get("signer_id")

            if msg_type == "round1_output" and signer_id not in self.session_data["round1_inputs"]:
                print(f"[Coordinator] Signer {signer_id} からラウンド1のデータを受信しました。")
                self.session_data["round1_inputs"][signer_id] = payload
                if len(self.session_data["round1_inputs"]) == self.num_signers:
                    self._start_round2()

            elif msg_type == "round2_output" and signer_id not in self.session_data["round2_inputs"]:
                print(f"[Coordinator] Signer {signer_id} からラウンド2の部分署名を受信しました。")
                self.session_data["round2_inputs"][signer_id] = payload
                if len(self.session_data["round2_inputs"]) == self.num_signers:
                    self._aggregate_and_verify()
        except (json.JSONDecodeError, KeyError) as e:
            if not msg.payload: return
            print(f"[Coordinator] 不正なメッセージを受信: {e}")

    def start_session(self):
        print(f"\n--- 新しい署名セッションを開始します (ID: {self.session_id}) ---")
        msg = {"session_id": self.session_id, "type": "session_start"}
        self.client.publish("dahlias/session/start", json.dumps(msg), qos=1, retain=True)

    def _start_round2(self):
        print("\n[Coordinator] 全員のラウンド1データが揃いました。ラウンド2を開始します。")
        
        sorted_signer_ids = sorted(self.session_data["round1_inputs"].keys())
        first_signer_data = self.session_data["round1_inputs"][sorted_signer_ids[0]]
        R1_agg_point = hex_to_point(first_signer_data['R1_hex'])
        R2_agg_point = hex_to_point(first_signer_data['R2_hex'])
        
        for signer_id in sorted_signer_ids[1:]:
            data = self.session_data["round1_inputs"][signer_id]
            R1_agg_point += hex_to_point(data['R1_hex'])
            R2_agg_point += hex_to_point(data['R2_hex'])

        L_tuples = []
        for signer_id in sorted_signer_ids:
            data = self.session_data["round1_inputs"][signer_id]
            L_tuples.append({ "pk_hex": data['pk_hex'], "message": data['message'], "R2_hex": data['R2_hex'] })

        ctx = { "R1_agg_hex": point_to_hex(R1_agg_point), "R2_agg_hex": point_to_hex(R2_agg_point), "L_tuples": L_tuples }
        self.session_data["ctx"] = ctx

        b_hash_input = {k: ctx[k] for k in sorted(ctx)}
        b = string_to_number(deterministic_hash(b_hash_input))
        self.session_data["final_R_point"] = R1_agg_point + b * R2_agg_point

        msg = { "session_id": self.session_id, "type": "round2_start_ctx", "payload": ctx }
        topic = f"dahlias/{self.session_id}/coordinator/to/signers"
        self.client.publish(topic, json.dumps(msg))
        print("[Coordinator] ctxを全署名者にブロードキャストしました。")

    def _aggregate_and_verify(self):
        print("\n[Coordinator] 全員の部分署名が揃いました。集約と検証を行います。")
        
        s_agg = 0
        for signer_id, data in self.session_data["round2_inputs"].items():
            s_agg += hex_to_int(data['s_i_hex'])
        s_agg %= G.order()
        
        final_R_point = self.session_data["final_R_point"]
        final_signature = {"R_hex": point_to_hex(final_R_point), "s_hex": int_to_hex(s_agg)}
        
        print(f"\n--- 生成された集約署名 ---")
        print(f"R: {final_signature['R_hex']}")
        print(f"s: {final_signature['s_hex']}")
        
        print("\n--- 検証を開始します ---")
        
        s = s_agg
        R = final_R_point
        ctx = self.session_data["ctx"]
        L_tuples = ctx['L_tuples']
        
        right_hand_side = R
        L = [(item['pk_hex'], item['message']) for item in L_tuples]
        
        for item in L_tuples:
            pk_point = hex_to_point(item['pk_hex'])
            message = item['message']
            c_hash_input = {'L': L, 'R_hex': point_to_hex(R), 'pk_hex': item['pk_hex'], 'message': message}
            c = string_to_number(deterministic_hash(c_hash_input))
            
            right_hand_side += c * pk_point
            
        left_hand_side = s * G
        
        if left_hand_side.to_affine() == right_hand_side.to_affine():
            print("\n✅✅✅ 検証成功！署名は正当です。 ✅✅✅")
        else:
            print("\n❌❌❌ 検証失敗！署名は不正です。 ❌❌❌")
            print(f"LHS: {point_to_hex(left_hand_side)}")
            print(f"RHS: {point_to_hex(right_hand_side)}")
        
        self.verification_complete.set()

    def cleanup_retained_messages(self):
        """セッション終了時にretained messageをクリアする"""
        self.client.publish("dahlias/session/start", "", qos=1, retain=True)

# --- メイン処理 ---
if __name__ == "__main__":
    NUM_SIGNERS = 3
    
    coordinator = Coordinator(NUM_SIGNERS)
    signers = []
    for i in range(NUM_SIGNERS):
        message = f"IoT device {i+1} reporting its status at {int(time.time())}"
        signer = Signer(signer_id=i+1, message=message)
        signers.append(signer)
        time.sleep(0.1) 
    
    all_clients = [coordinator] + signers
    for client_obj in all_clients:
        client_obj.connect()

    print("\n--- 全クライアントの接続を待機中... ---")
    for client_obj in all_clients:
        client_obj.connected_event.wait(timeout=10)
    print("--- 全クライアントの接続が完了しました。 ---")
    
    coordinator.start_session()
    
    print("\n--- プロトコル実行中...完了まで待機します ---")
    completed = coordinator.verification_complete.wait(timeout=30)
    
    if not completed:
        print("\nタイムアウトしました。プロトコルが完了しませんでした。")

    print("\n--- プロトコル終了。接続を切断します ---")
    coordinator.cleanup_retained_messages()
    time.sleep(0.5) # メッセージが送信されるのを少し待つ
    for client_obj in all_clients:
        client_obj.client.loop_stop()
        client_obj.client.disconnect()