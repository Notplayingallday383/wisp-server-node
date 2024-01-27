const WebSocket = require('ws');
const http = require('http');
const fs = require('fs').promises;
const path = require('path');
const mimetypes = require('mime-types');

const tcpSize = 64 * 1024;
const queueSize = 128;
let staticPath = null;

// wisp packet format definitions
// see https://docs.python.org/3/library/struct.html for what these characters mean
const packetFormat = "<BI";
const connectFormat = "<BH";
const continueFormat = "<B";
const closeFormat = "<B";

class WSProxyConnection {
  constructor(ws, path) {
    this.ws = ws;
    this.path = path;
  }

  async setupConnection() {
    const addrStr = this.path.split("/").pop();
    [this.tcpHost, this.tcpPort] = addrStr.split(":");
    this.tcpPort = parseInt(this.tcpPort, 10);

    [this.tcpReader, this.tcpWriter] = await asyncio.openConnection({
      host: this.tcpHost,
      port: this.tcpPort,
      limit: tcpSize,
    });
  }

  async handleWs() {
    while (true) {
      try {
        const data = await this.ws.recv();
      } catch (error) {
        break;
      }
      this.tcpWriter.write(data);
      await this.tcpWriter.drain();
    }

    this.tcpWriter.close();
  }

  async handleTcp() {
    while (true) {
      const data = await this.tcpReader.read(tcpSize);
      if (data.length === 0) {
        break; // socket closed
      }
      await this.ws.send(data);
    }

    await this.ws.close();
  }
}

class WispConnection {
  constructor(ws, path) {
    this.ws = ws;
    this.path = path;
    this.activeStreams = {};
  }

  // send the initial CONTINUE packet
  async setup() {
    const continuePayload = struct.pack(continueFormat, queueSize);
    const continuePacket = struct.pack(packetFormat, 0x03, 0) + continuePayload;
    await this.ws.send(continuePacket);
  }

  async newStream(streamId, payload) {
    const [streamType, destinationPort] = struct.unpack(connectFormat, payload.slice(0, 3));
    const hostname = payload.slice(3).toString();

    if (streamType !== 1) {
      // UDP not supported yet
      await this.sendClosePacket(streamId, 0x41);
      this.closeStream(streamId);
      return;
    }

    try {
      const [tcpReader, tcpWriter] = await asyncio.openConnection({
        host: hostname,
        port: destinationPort,
        limit: tcpSize,
      });
    } catch (error) {
      await this.sendClosePacket(streamId, 0x42);
      this.closeStream(streamId);
      return;
    }

    this.activeStreams[streamId].reader = tcpReader;
    this.activeStreams[streamId].writer = tcpWriter;

    const wsToTcpTask = asyncio.createTask(this.taskWrapper(this.streamWsToTcp, streamId));
    const tcpToWsTask = asyncio.createTask(this.taskWrapper(this.streamTcpToWs, streamId));
    this.activeStreams[streamId].wsToTcpTask = wsToTcpTask;
    this.activeStreams[streamId].tcpToWsTask = tcpToWsTask;
  }

  async taskWrapper(targetFunc, ...args) {
    try {
      await targetFunc(...args);
    } catch (e) {
      throw e;
    }
  }

  async streamWsToTcp(streamId) {
    // this infinite loop should get killed by the task.cancel call later on
    while (true) {
      const stream = this.activeStreams[streamId];
      const data = await stream.queue.get();
      stream.writer.write(data);
      try {
        await stream.writer.drain();
      } catch (error) {
        break;
      }

      // send a CONTINUE packet periodically
      stream.packetsSent += 1;
      if (stream.packetsSent % (queueSize / 4) === 0) {
        const bufferRemaining = stream.queue.maxsize - stream.queue.qsize();
        const continuePayload = struct.pack(continueFormat, bufferRemaining);
        const continuePacket = struct.pack(packetFormat, 0x03, streamId) + continuePayload;
        await this.ws.send(continuePacket);
      }
    }
  }

  async streamTcpToWs(streamId) {
    while (true) {
      const stream = this.activeStreams[streamId];
      const data = await stream.reader.read(tcpSize);
      if (data.length === 0) {
        // connection closed
        break;
      }
      const dataPacket = struct.pack(packetFormat, 0x02, streamId) + data;
      await this.ws.send(dataPacket);
    }

    await this.sendClosePacket(streamId, 0x02);
    this.closeStream(streamId);
  }

  async sendClosePacket(streamId, reason) {
    if (!this.activeStreams[streamId]) {
      return;
    }
    const closePayload = struct.pack(closeFormat, reason);
    const closePacket = struct.pack(packetFormat, 0x04, streamId) + closePayload;
    await this.ws.send(closePacket);
  }

  closeStream(streamId) {
    if (!this.activeStreams[streamId]) {
      return; // stream already closed
    }
    const stream = this.activeStreams[streamId];
    this.closeTcp(stream.writer);

    // kill the running tasks associated with this stream
    if (!stream.connectTask.done()) {
      stream.connectTask.cancel();
    }
    if (stream.wsToTcpTask !== null && !stream.wsToTcpTask.done()) {
      stream.wsToTcpTask.cancel();
    }
    if (stream.tcpToWsTask !== null && !stream.tcpToWsTask.done()) {
      stream.tcpToWsTask.cancel();
    }

    delete this.activeStreams[streamId];
  }

  closeTcp(tcpWriter) {
    if (tcpWriter === null) {
      return;
    }
    if (tcpWriter.readyState === WebSocket.CLOSING) {
      return;
    }
    tcpWriter.close();
  }

  async handleWs() {
    while (true) {
      try {
        const data = await this.ws.recv();
      } catch (error) {
        break;
      }

      // get basic packet info
      const payload = data.slice(5);
      const [packetType, streamId] = data.slice(0, 5).unpack(packetFormat);

      if (packetType === 0x01) {
        // CONNECT packet
        const connectTask = asyncio.createTask(this.taskWrapper(this.newStream, streamId, payload));
        this.activeStreams[streamId] = {
          reader: null,
          writer: null,
          queue: new asyncio.Queue(queueSize),
          connectTask: connectTask,
          wsToTcpTask: null,
          tcpToWsTask: null,
          packetsSent: 0,
        };
      } else if (packetType === 0x02) {
        // DATA packet
        const stream = this.activeStreams[streamId];
        if (!stream) {
          continue;
        }
        await stream.queue.put(payload);
      } else if (packetType === 0x04) {
        // CLOSE packet
        const reason = payload.unpack(closeFormat)[0];
        this.closeStream(streamId);
      }
    }

    // close all active streams when the websocket disconnects
    for (const streamId of Object.keys(this.activeStreams)) {
      this.closeStream(parseInt(streamId, 10));
    }
  }
}

async function connectionHandler(websocket, path) {
  console.log(`Incoming connection from ${path}`);
  if (path.endsWith("/")) {
    const connection = new WispConnection(websocket, path);
    await connection.setup();
    const wsHandler = connection.handleWs();
    await asyncio.gather(wsHandler);
  } else {
    const connection = new WSProxyConnection(websocket, path);
    await connection.setupConnection();
    const wsHandler = connection.handleWs();
    const tcpHandler = connection.handleTcp();
    await asyncio.gather(wsHandler, tcpHandler);
  }
}

async function staticHandler(filePath, requestHeaders) {
  if ("Upgrade" in requestHeaders) {
    return;
  }

  const responseHeaders = [
    ["Server", "JavaScript Wisp Server"],
  ];

  const targetPath = path.resolve(staticPath || "", filePath.slice(1));

  try {
    const stat = await fs.stat(targetPath);
    if (!stat.isFile()) {
      return [403, responseHeaders, "403 forbidden, disallowed path"];
    }
  } catch (error) {
    if (error.code === 'ENOENT') {
      return [404, responseHeaders, "404 not found"];
    }
    throw error;
  }
  

  if (fs.statSync(targetPath).isDirectory()) {
    filePath = path.join(filePath, "index.html");
  }

  const mimeType = mimetypes.lookup(targetPath) || "application/octet-stream";
  responseHeaders.push(["Content-Type", mimeType]);

  const staticData = await fs.readFile(targetPath);
  return [200, responseHeaders, staticData];
}

async function main() {
  const host = process.env.HOST || "127.0.0.1";
  const port = parseInt(process.env.PORT || "6001", 10);
  const staticDir = process.env.STATIC;

  if (staticDir) {
    staticPath = path.resolve(staticDir);
  } else {
    staticPath = path.resolve(".");
  }
  mimetypes.types;

  console.log(`Serving static files from ${staticPath}`);
  console.log(`Listening on ${host}:${port}`);

  const server = new WebSocket.Server({ noServer: true, subprotocol: ["wisp-v1"] });
  server.on("connection", connectionHandler);

  const httpServer = http.createServer(async (request, response) => {
    const [status, headers, body] = await staticHandler(request.url || "", request.headers);
    response.writeHead(status, headers);
    response.end(body);
  });

  httpServer.on("upgrade", (request, socket, head) => {
    server.handleUpgrade(request, socket, head, (ws) => {
      server.emit("connection", ws, request.url);
    });
  });

  httpServer.listen(port, host);
}

if (require.main === module) {
  main();
}
