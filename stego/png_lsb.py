from stegano import lsb
import base64, json
def hide_to_png(input_png: str, output_png: str, payload: dict):
    msg = base64.b64encode(json.dumps(payload).encode()).decode()
    lsb.hide(input_png, msg).save(output_png)
def reveal_from_png(png_path: str) -> dict:
    msg = lsb.reveal(png_path)
    return json.loads(base64.b64decode(msg.encode()).decode())
