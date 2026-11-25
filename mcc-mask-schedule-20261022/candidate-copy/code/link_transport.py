"""Existing LegacyWorkspace LINK_FRAG port; bounded, no acknowledgement added.
Compact-candidate frames <=1060 UDP bytes; IP28 + future mask-header64 <=1152.
Reassembly precedes the unchanged hop AEAD verification. Shared lab config is unchanged.
"""
import base64
import secrets
import time
from typing import Optional
from protocol import jdump, jload
T_LINK_FRAG = 'LINK_FRAG'
LINK_FRAG_MAX_WIRE = 1060
LINK_FRAG_CHUNK_BYTES = 714
LINK_FRAG_TTL_S = 15
LINK_CIPHER_VERSION = 2
LINK_MAX_CIPHERTEXT = 65507
LINK_MAX_BASE64 = 4 * ((LINK_MAX_CIPHERTEXT + 2) // 3)


def link_aad(mtype, sender, recipient, sid):
    # Wire version is authenticated, not inferred from ciphertext characters.
    return f'link/v2:{mtype}:{sender}->{recipient}:{sid}'.encode('utf-8')


def link_envelope(mtype, sender, recipient, sid, nonce, ciphertext, meta=None):
    if len(nonce) != 12 or not 16 <= len(ciphertext) <= LINK_MAX_CIPHERTEXT:
        raise ValueError('Invalid compact link encryption output')
    return {'lv': LINK_CIPHER_VERSION, 't': mtype, 'sid': sid, 'from': sender,
            'to': recipient, 'nonce': nonce.hex(),
            'ct': base64.b64encode(ciphertext).decode('ascii'), 'meta': meta or {}}


def link_ciphertext(message):
    # No legacy fallback or alternate spelling; retain bounded parsing before AEAD.
    if type(message.get('lv')) is not int or message['lv'] != LINK_CIPHER_VERSION:
        raise ValueError('Unsupported compact link wire version')
    encoded = message.get('ct')
    if type(encoded) is not str or not 24 <= len(encoded) <= LINK_MAX_BASE64 or len(encoded) % 4:
        raise ValueError('Invalid compact ciphertext size')
    try:
        raw = base64.b64decode(encoded.encode('ascii'), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError('Invalid compact ciphertext encoding') from exc
    if not 16 <= len(raw) <= LINK_MAX_CIPHERTEXT or base64.b64encode(raw).decode('ascii') != encoded:
        raise ValueError('Noncanonical compact ciphertext')
    return raw

class LinkTransportMixin:
    def _init_link_transport(self):
        self.link_frag_buf = {}

    def send_peer(self, peer: str, payload: bytes):
        if peer == self.name:
            self.logger.error(f"[BUG] attempt to send to self peer={peer} DROP")
            return
        if len(payload) <= LINK_FRAG_MAX_WIRE:
            self._send_peer_raw(peer, payload)
            return
        frag_id = secrets.token_hex(8)
        if len(payload) > 65507:
            raise ValueError('Overlay message exceeds bounded transport size')
        chunks = [payload[i:i + LINK_FRAG_CHUNK_BYTES] for i in range(0, len(payload), LINK_FRAG_CHUNK_BYTES)]
        total = len(chunks)
        self.logger.debug(
            f"[LINK/FRAG] send peer={peer} bytes={len(payload)} fragments={total} "
            f"chunk={LINK_FRAG_CHUNK_BYTES} frag={frag_id}"
        )
        frames = []
        for seq, chunk in enumerate(chunks):
            frag = {
                "t": T_LINK_FRAG,
                "from": self.name,
                "to": peer,
                "frag_id": frag_id,
                "seq": seq,
                "total": total,
                "data": base64.b64encode(chunk).decode("ascii"),
            }
            frame = jdump(frag)
            if len(frame) > LINK_FRAG_MAX_WIRE:
                raise ValueError('Fragment header exceeds compact frame budget')
            frames.append(frame)
        # Validate every frame before emitting any part of this message.
        for frame in frames:
            self._send_peer_raw(peer, frame)

    def _handle_link_frag(self, p: dict, peer: str) -> Optional[bytes]:
        if not peer or p.get("from") != peer or p.get("to") != self.name:
            self.logger.warning(f"[LINK/FRAG] drop invalid endpoint peer={peer} from={p.get('from')} to={p.get('to')}")
            return None
        try:
            frag_id = str(p.get("frag_id", ""))
            seq = int(p.get("seq", -1))
            total = int(p.get("total", 0))
            data = base64.b64decode(str(p.get("data", "")).encode("ascii"), validate=True)
        except Exception as e:
            self.logger.warning(f"[LINK/FRAG] bad fragment from={peer}: {e}")
            return None
        if not frag_id or total <= 0 or seq < 0 or seq >= total or total > 94 or len(data) > LINK_FRAG_CHUNK_BYTES or len(frag_id) != 16:
            self.logger.warning(f"[LINK/FRAG] invalid fragment header from={peer} frag={frag_id} seq={seq}/{total}")
            return None
        now = time.time()
        key = f"{peer}:{frag_id}"
        with self.lock:
            for old_key, entry in list(self.link_frag_buf.items()):
                if now - float(entry.get("created_at", now)) > LINK_FRAG_TTL_S:
                    self.link_frag_buf.pop(old_key, None)
            if key not in self.link_frag_buf and len(self.link_frag_buf) >= 32:
                return None
            entry = self.link_frag_buf.setdefault(key, {"created_at": now, "total": total, "parts": {}})
            if int(entry.get("total", total)) != total:
                self.link_frag_buf.pop(key, None)
                self.logger.warning(f"[LINK/FRAG] total mismatch from={peer} frag={frag_id}")
                return None
            previous = entry['parts'].get(seq)
            if previous is not None and previous != data:
                self.link_frag_buf.pop(key, None)
                return None
            entry["parts"][seq] = data
            if len(entry["parts"]) < total:
                return None
            parts = entry["parts"]
            self.link_frag_buf.pop(key, None)
        try:
            assembled = b"".join(parts[i] for i in range(total))
        except KeyError:
            return None
        self.logger.debug(f"[LINK/FRAG] reassembled from={peer} bytes={len(assembled)} fragments={total} frag={frag_id}")
        if len(assembled) > 65507:
            return None
        try:
            if jload(assembled).get('t') == T_LINK_FRAG:
                return None
        except (ValueError, AttributeError):
            return None
        return assembled
