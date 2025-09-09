import asyncio, struct, json, uuid

async def send_request_via_unix(path, method, params):
    reader, writer = await asyncio.open_unix_connection(path)
    try:
        req = {"id": str(uuid.uuid4()), "method": method, "params": params}
        data = json.dumps(req).encode()
        writer.write(struct.pack(">I", len(data)))
        writer.write(data)
        await writer.drain()
        len_bytes = await reader.readexactly(4)
        resp_len = struct.unpack(">I", len_bytes)[0]
        resp_data = await reader.readexactly(resp_len)
        return json.loads(resp_data.decode())
    finally:
        writer.close()
        await writer.wait_closed()

async def send_request_via_tcp(host, port, method, params):
    reader, writer = await asyncio.open_connection(host, port)
    try:
        req = {"id": str(uuid.uuid4()), "method": method, "params": params}
        data = json.dumps(req).encode()
        writer.write(struct.pack(">I", len(data))); writer.write(data)
        await writer.drain()
        len_bytes = await reader.readexactly(4)
        resp_len = struct.unpack(">I", len_bytes)[0]
        resp_data = await reader.readexactly(resp_len)
        return json.loads(resp_data.decode())
    finally:
        writer.close(); await writer.wait_closed()
