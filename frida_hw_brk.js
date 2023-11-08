function log(msg) {
    console.log(`${msg}`);
}

async function SetHWBrk(brk_addr, brk_type) {
    try {
        let size_len = 4;

        let brk_options = {
            brk_pid: Process.id,
            brk_len: 4,
            brk_type: brk_type,
            brk_addr: brk_addr,
        };
        // open conn
        log(`[SetHWBrk] open conn`);
        // stackplz --rpc-path
        let conn = await Socket.connect({
            family: "ipv4",
            host: "localhost",
            port: 41718,
        });
    
        let payload = JSON.stringify(brk_options);
        log(`brk_options -> ${payload}`);

        let msg_len = payload.length;
    
        // send payload size
        let size_buffer = Memory.alloc(size_len);
        size_buffer.writeU32(msg_len);
        await conn.output.writeAll(size_buffer.readByteArray(size_len));
        
        // send payload
        let payload_buffer = Memory.alloc(payload.length);
        payload_buffer.writeUtf8String(payload);
        await conn.output.writeAll(payload_buffer.readByteArray(payload.length));
    
        // try read resp size
        let resp_size_buffer = await conn.input.readAll(size_len);
        let resp_size = resp_size_buffer.unwrap().readU32();
        let resp = await conn.input.readAll(resp_size);
        log(`resp -> ${hexdump(resp)}`);
        // close conn
        await conn.close();
    } catch (error) {
        log(`[SetHWBrk] error ${error}`);
    }
}

function do_hw_brk() {
    // modify here
    try {
        let lib = Process.getModuleByName("libnative-lib.so");
        SetHWBrk(lib.base.add(0xaaaa), "rw");
        SetHWBrk(lib.base.add(0x1111), "x");
    } catch (error) {
    log(`error ${error}`);
    }
}

rpc.exports = {
    do_hw_brk: do_hw_brk
}

// ./stackplz --rpc --stack
// ./stackplz --rpc --stack --mstack
// ./stackplz --rpc --stack --mstack --regs
// ./stackplz --rpc --rpc-path 127.0.0.1:12345 --stack

// repl call rpc.exports.do_hw_brk()