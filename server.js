
const express = require("express");
const multer = require("multer");
const QRCode = require("qrcode");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
const DATA_FILE = path.join(DATA_DIR, "data.json");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const PIX_KEY = process.env.PIX_KEY || "91989935507";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(48).toString("hex");
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "adm";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "1234";
const IS_PROD = process.env.NODE_ENV === "production";
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN || "";
const MP_WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET || "";
const PUBLIC_URL = (process.env.PUBLIC_URL || "").replace(/\/$/, "");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const DEFAULT_DB = {
  version: 2,
  admin: { username: ADMIN_USERNAME, passwordHash: null },
  pixKey: PIX_KEY,
  events: [],
  organizers: [],
  orders: []
};

function makeId(prefix) {
  return `${prefix}-${crypto.randomBytes(6).toString("hex").toUpperCase()}`;
}

function loadDB() {
  let data = null;
  if (fs.existsSync(DATA_FILE)) {
    try { data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); } catch (_) {}
  }
  data = data || structuredClone(DEFAULT_DB);
  data.admin = data.admin || structuredClone(DEFAULT_DB.admin);
  data.admin.username = data.admin.username || ADMIN_USERNAME;
  data.events = Array.isArray(data.events) ? data.events : [];
  data.organizers = Array.isArray(data.organizers) ? data.organizers : [];
  data.orders = Array.isArray(data.orders) ? data.orders : [];
  data.pixKey = data.pixKey || PIX_KEY;

  // Migração segura: versões anteriores guardavam a senha em texto.
  if (!data.admin.passwordHash) {
    const old = data.admin.password;
    data.admin.passwordHash = bcrypt.hashSync(old || ADMIN_PASSWORD, 12);
    delete data.admin.password;
  }
  for (const o of data.organizers) {
    if (!o.passwordHash && o.password) {
      o.passwordHash = bcrypt.hashSync(o.password, 12);
      delete o.password;
    }
  }
  saveDB(data);
  return data;
}

let db;
function saveDB(next = db) {
  const tmp = DATA_FILE + ".tmp";
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(next, null, 2), "utf8");
  fs.renameSync(tmp, DATA_FILE);
}
db = loadDB();

app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Muitas tentativas de login. Aguarde alguns minutos." }
});
app.use("/api/login", loginLimiter);

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const ok = ["image/jpeg", "image/png", "image/webp"].includes(file.mimetype);
    cb(ok ? null : new Error("A foto precisa ser JPG, PNG ou WEBP."), ok);
  }
});

function publicEvent(e) {
  return {
    id: e.id, name: e.name, description: e.description || "",
    date: e.date || "", time: e.time || "", location: e.location || "",
    image: e.image || "", active: e.active !== false,
    tickets: (e.tickets || []).map(t => ({
      id: t.id, name: t.name, price: Number(t.price) || 0,
      stock: Number(t.stock) || 0, sold: Number(t.sold) || 0
    }))
  };
}

function signSession(payload) {
  return jwt.sign(payload, SESSION_SECRET, { expiresIn: "12h", issuer: "partiu" });
}
function getSession(req) {
  const token = req.cookies?.partiu_session;
  if (!token) return null;
  try {
    return jwt.verify(token, SESSION_SECRET, { issuer: "partiu" });
  } catch (_) { return null; }
}

function requireRole(role) {
  return (req, res, next) => {
    const s = getSession(req);
    if (s && s.role === role) return next();
    return res.status(401).json({ error: "Sessão inválida ou expirada. Faça login novamente." });
  };
}

// Pequeno cookie parser sem dependência extra.
app.use((req, _, next) => {
  const raw = req.headers.cookie || "";
  req.cookies = {};
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) req.cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  next();
});

app.get("/api/health", (_, res) => {
  res.json({ ok: true, service: "PARTIU", database: "persistent-json", pixKey: db.pixKey });
});

app.get("/api/config", (_, res) => res.json({ pixKey: db.pixKey }));

app.get("/api/me", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, ...s });
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!username || !password) return res.status(400).json({ error: "Informe usuário e senha." });

  let role = null, user = null;
  if (username === db.admin.username && await bcrypt.compare(password, db.admin.passwordHash)) {
    role = "admin";
    user = { username: db.admin.username };
  } else {
    const org = db.organizers.find(o => o.username.toLowerCase() === username.toLowerCase());
    if (org && await bcrypt.compare(password, org.passwordHash)) {
      role = "organizer";
      user = {
        username: org.username, organizerId: org.id, eventId: org.eventId,
        eventName: db.events.find(e => e.id === org.eventId)?.name || ""
      };
    }
  }
  if (!role) return res.status(401).json({ error: "Usuário ou senha inválidos." });

  const session = { role, username: user.username, organizerId: user.organizerId, eventId: user.eventId };
  const token = signSession(session);
  res.cookie("partiu_session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    maxAge: 12 * 60 * 60 * 1000,
    path: "/"
  });
  res.json(session);
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("partiu_session", { httpOnly: true, sameSite: "lax", secure: IS_PROD, path: "/" });
  res.json({ ok: true });
});

// Público
app.use("/uploads", express.static(UPLOAD_DIR, {
  maxAge: "7d",
  immutable: true
}));
app.get("/api/events", (_, res) => {
  res.json(db.events.filter(e => e.active !== false).map(publicEvent));
});
app.get("/api/events/:id", (req, res) => {
  const event = db.events.find(e => e.id === req.params.id);
  if (!event) return res.status(404).json({ error: "Evento não encontrado." });
  res.json(publicEvent(event));
});

// ADM
app.get("/api/admin/events", requireRole("admin"), (_, res) => res.json(db.events.map(publicEvent)));

app.post("/api/events", requireRole("admin"), upload.single("image"), (req, res) => {
  let tickets = [];
  try { tickets = JSON.parse(req.body.ticketsJson || "[]"); } catch (_) {}
  tickets = tickets.filter(t => String(t.name || "").trim()).map(t => ({
    id: makeId("ING"), name: String(t.name).trim(),
    price: Math.max(0, Number(t.price) || 0),
    stock: Math.max(0, Number(t.stock) || 0), sold: 0
  }));
  if (!String(req.body.name || "").trim()) return res.status(400).json({ error: "Informe o nome do evento." });
  if (!tickets.length) return res.status(400).json({ error: "Cadastre pelo menos um ingresso." });

  const event = {
    id: makeId("EVT"), name: String(req.body.name).trim(),
    description: req.body.description || "", date: req.body.date || "",
    time: req.body.time || "", location: req.body.location || "",
    image: req.file ? `/uploads/${req.file.filename}` : "",
    active: true, tickets, createdAt: new Date().toISOString()
  };
  db.events.push(event); saveDB();
  res.status(201).json(publicEvent(event));
});

app.put("/api/events/:id", requireRole("admin"), upload.single("image"), (req, res) => {
  const event = db.events.find(e => e.id === req.params.id);
  if (!event) return res.status(404).json({ error: "Evento não encontrado." });
  event.name = String(req.body.name || event.name).trim();
  event.description = req.body.description ?? event.description;
  event.date = req.body.date ?? event.date;
  event.time = req.body.time ?? event.time;
  event.location = req.body.location ?? event.location;
  if (req.file) event.image = `/uploads/${req.file.filename}`;
  if (req.body.ticketsJson) {
    let incoming = [];
    try { incoming = JSON.parse(req.body.ticketsJson); } catch (_) {}
    event.tickets = incoming.filter(t => String(t.name || "").trim()).map(t => {
      const old = event.tickets.find(x => x.id === t.id);
      return {
        id: old?.id || makeId("ING"), name: String(t.name).trim(),
        price: Math.max(0, Number(t.price) || 0),
        stock: Math.max(Number(old?.sold || 0), Number(t.stock) || 0),
        sold: Number(old?.sold || 0)
      };
    });
  }
  saveDB(); res.json(publicEvent(event));
});

app.get("/api/admin/organizers", requireRole("admin"), (_, res) => res.json(
  db.organizers.map(o => ({
    id:o.id, name:o.name, username:o.username, eventId:o.eventId,
    eventName:db.events.find(e=>e.id===o.eventId)?.name||""
  }))
));

app.post("/api/organizers", requireRole("admin"), async (req, res) => {
  const name=String(req.body.name||"").trim(), username=String(req.body.username||"").trim();
  const password=String(req.body.password||""), eventId=String(req.body.eventId||"");
  if(!name||!username||!password||!eventId) return res.status(400).json({error:"Preencha nome, usuário, senha e evento."});
  if(password.length < 6) return res.status(400).json({error:"A senha do Organizador precisa ter pelo menos 6 caracteres."});
  if(!db.events.some(e=>e.id===eventId)) return res.status(400).json({error:"O evento escolhido não existe."});
  if(db.organizers.some(o=>o.username.toLowerCase()===username.toLowerCase())) return res.status(409).json({error:"Esse usuário já está cadastrado."});
  const organizer={id:makeId("ORG"),name,username,passwordHash:await bcrypt.hash(password,12),eventId};
  db.organizers.push(organizer); saveDB();
  res.status(201).json({id:organizer.id,name,username,eventId,eventName:db.events.find(e=>e.id===eventId)?.name||""});
});

app.get("/api/admin/dashboard", requireRole("admin"), (_, res) => {
  const confirmed=db.orders.filter(o=>o.status==="CONFIRMADO");
  res.json({
    events:db.events.length, organizers:db.organizers.length, orders:db.orders.length,
    pending:db.orders.filter(o=>o.status==="PENDENTE").length,
    confirmed:confirmed.length,
    revenue:confirmed.reduce((s,o)=>s+Number(o.total||0),0)
  });
});
app.get("/api/admin/orders", requireRole("admin"), (_, res) => res.json(db.orders));

function crc16(payload) {
  let crc=0xFFFF;
  for(let i=0;i<payload.length;i++){crc^=payload.charCodeAt(i)<<8;for(let j=0;j<8;j++)crc=(crc&0x8000)?((crc<<1)^0x1021)&0xFFFF:(crc<<1)&0xFFFF;}
  return crc.toString(16).toUpperCase().padStart(4,"0");
}
function tlv(id,value){value=String(value);return id+String(value.length).padStart(2,"0")+value;}
function makePix(key,amount,txid){
  let payload=tlv("00","01")+tlv("26",tlv("00","BR.GOV.BCB.PIX")+tlv("01",key))+tlv("52","0000")+tlv("53","986")+tlv("54",Number(amount).toFixed(2))+tlv("58","BR")+tlv("59","PARTIU")+tlv("60","BELEM")+tlv("62",tlv("05",txid.slice(0,25)));
  return payload+"6304"+crc16(payload+"6304");
}


async function mpRequest(method, endpoint, body, extraHeaders={}) {
  if (!MP_ACCESS_TOKEN) throw new Error("Mercado Pago não configurado no servidor.");
  const response = await fetch(`https://api.mercadopago.com${endpoint}`, {
    method,
    headers: { Authorization: `Bearer ${MP_ACCESS_TOKEN}`, "Content-Type": "application/json", ...extraHeaders },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch (_) { data = { raw: text }; }
  if (!response.ok) {
    const msg = data?.message || data?.error || `Mercado Pago HTTP ${response.status}`;
    throw new Error(msg);
  }
  return data;
}

function validWebhookSignature(req) {
  if (!MP_WEBHOOK_SECRET) return !IS_PROD;
  const signature = String(req.headers["x-signature"] || "");
  const requestId = String(req.headers["x-request-id"] || "");
  const dataId = String(req.query?.["data.id"] || req.body?.data?.id || "");
  if (!signature || !requestId || !dataId) return false;
  const parts = Object.fromEntries(signature.split(",").map(x => x.split("=").map(v => v.trim())).filter(x => x.length === 2));
  if (!parts.ts || !parts.v1) return false;
  const manifest = `id:${dataId.toLowerCase()};request-id:${requestId};ts:${parts.ts};`;
  const expected = crypto.createHmac("sha256", MP_WEBHOOK_SECRET).update(manifest).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1)); } catch (_) { return false; }
}

async function confirmFromMercadoPago(paymentId) {
  const payment = await mpRequest("GET", `/v1/payments/${encodeURIComponent(paymentId)}`);
  if (payment.status !== "approved") return { ok: true, approved: false, status: payment.status };
  const orderId = String(payment.external_reference || "");
  const order = db.orders.find(o => o.id === orderId);
  if (!order) return { ok: true, approved: true, ignored: true };
  if (Math.abs(Number(payment.transaction_amount || 0) - Number(order.total || 0)) > 0.01) {
    throw new Error("Valor do pagamento diferente do pedido.");
  }
  if (order.status !== "CONFIRMADO") {
    order.status = "CONFIRMADO";
    order.confirmedAt = new Date().toISOString();
    order.paymentStatus = payment.status;
    order.paymentId = String(payment.id);
    order.ticketCode = order.ticketCode || `PARTIU-${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
    order.ticketQrCodeDataUrl = await QRCode.toDataURL(order.ticketCode, { width: 320, margin: 2 });
    saveDB();
  }
  return { ok: true, approved: true, orderId: order.id };
}

app.post("/api/webhooks/mercadopago", async (req, res) => {
  if (!validWebhookSignature(req)) return res.status(401).json({ error: "Webhook inválido." });
  const type = String(req.body?.type || req.body?.topic || "");
  if (type === "payment" || req.body?.action === "payment.updated") {
    const paymentId = String(req.body?.data?.id || req.query?.id || "");
    if (paymentId) {
      try { await confirmFromMercadoPago(paymentId); } catch (e) { console.error("Mercado Pago webhook:", e.message); }
    }
  }
  return res.sendStatus(200);
});

app.post("/api/orders", async (req,res)=>{
  try {
    if (!MP_ACCESS_TOKEN) return res.status(503).json({ error: "Pagamento PIX automático ainda não foi configurado no servidor." });
    if (IS_PROD && !PUBLIC_URL.startsWith("https://")) return res.status(503).json({ error: "PUBLIC_URL precisa ser HTTPS para o pagamento automático." });
    const event=db.events.find(e=>e.id===req.body.eventId&&e.active!==false);
    if(!event)return res.status(404).json({error:"Evento não encontrado."});
    const customer=req.body.customer||{};
    if(!customer.name||!customer.email||!customer.phone)return res.status(400).json({error:"Informe nome, e-mail e telefone."});
    const requested=Array.isArray(req.body.tickets)?req.body.tickets:[], lines=[]; let total=0;
    for(const item of requested){
      const ticket=event.tickets.find(t=>t.id===item.ticketId), quantity=Math.floor(Number(item.quantity)||0);
      if(!ticket||quantity<=0)continue;
      const available=ticket.stock-ticket.sold;
      if(quantity>available)return res.status(400).json({error:`Estoque insuficiente para ${ticket.name}.`});
      lines.push({ticketId:ticket.id,name:ticket.name,quantity,unitPrice:ticket.price}); total+=ticket.price*quantity;
    }
    if(!lines.length)return res.status(400).json({error:"Escolha pelo menos um ingresso."});
    const orderId=makeId("PED");
    const order={id:orderId,eventId:event.id,eventName:event.name,customer,tickets:lines,total,status:"PENDENTE",pixKey:db.pixKey,pixCopyPaste:"",qrCodeDataUrl:"",paymentId:null,paymentStatus:"pending",ticketCode:null,ticketQrCodeDataUrl:null,createdAt:new Date().toISOString(),confirmedAt:null};
    const payment=await mpRequest("POST","/v1/payments",{
      transaction_amount:Number(total.toFixed(2)),
      description:`Ingresso - ${event.name}`.slice(0,250),
      payment_method_id:"pix",
      external_reference:orderId,
      notification_url:`${PUBLIC_URL}/api/webhooks/mercadopago`,
      payer:{email:String(customer.email).trim(),first_name:String(customer.name).trim().slice(0,60)}
    },{"X-Idempotency-Key":orderId});
    const td=payment?.point_of_interaction?.transaction_data||{};
    order.paymentId=String(payment.id||"");
    order.paymentStatus=payment.status||"pending";
    order.pixCopyPaste=td.qr_code||"";
    order.pixQr=td.qr_code_base64||"";
    order.pixTicketUrl=td.ticket_url||"";
    if(!order.pixCopyPaste) return res.status(502).json({error:"O Mercado Pago não retornou o código PIX."});
    for(const line of lines){event.tickets.find(t=>t.id===line.ticketId).sold+=line.quantity;}
    db.orders.push(order); saveDB();
    res.status(201).json(order);
  } catch(e) {
    console.error("Criar pedido:", e);
    res.status(502).json({ error: e.message || "Não foi possível criar a cobrança PIX." });
  }
});
app.get("/api/orders/:id",(req,res)=>{const o=db.orders.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:"Pedido não encontrado."});res.json(o);});
app.post("/api/admin/orders/:id/confirm",requireRole("admin"),async (req,res)=>{
  const o=db.orders.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:"Pedido não encontrado."});
  if(o.status!=="CONFIRMADO"){o.status="CONFIRMADO";o.confirmedAt=new Date().toISOString();o.paymentStatus="approved";o.ticketCode=o.ticketCode||`PARTIU-${crypto.randomBytes(8).toString("hex").toUpperCase()}`;o.ticketQrCodeDataUrl=o.ticketQrCodeDataUrl||await QRCode.toDataURL(o.ticketCode,{width:320,margin:2});saveDB();}res.json(o);
});
app.post("/api/admin/orders/:id/cancel",requireRole("admin"),(req,res)=>{
  const o=db.orders.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:"Pedido não encontrado."});
  if(o.status!=="CANCELADO"){const e=db.events.find(x=>x.id===o.eventId);if(e)for(const l of o.tickets){const t=e.tickets.find(x=>x.id===l.ticketId);if(t)t.sold=Math.max(0,t.sold-l.quantity);}}
  o.status="CANCELADO";saveDB();res.json(o);
});

app.get("/api/organizer/report",requireRole("organizer"),(req,res)=>{
  const s=getSession(req), organizer=db.organizers.find(o=>o.id===s.organizerId);
  if(!organizer)return res.status(404).json({error:"Organizador não encontrado."});
  const event=db.events.find(e=>e.id===organizer.eventId), orders=db.orders.filter(o=>o.eventId===organizer.eventId);
  res.json({organizer:{id:organizer.id,name:organizer.name,username:organizer.username,eventId:organizer.eventId},event:event?publicEvent(event):null,orders,totals:{orders:orders.length,confirmed:orders.filter(o=>o.status==="CONFIRMADO").length,pending:orders.filter(o=>o.status==="PENDENTE").length,revenue:orders.filter(o=>o.status==="CONFIRMADO").reduce((s,o)=>s+Number(o.total||0),0)}});
});

app.get("/api/tickets/:orderId",(req,res)=>{
  const o=db.orders.find(x=>x.id===req.params.orderId);
  if(!o)return res.status(404).json({error:"Pedido não encontrado."});
  if(o.status!=="CONFIRMADO")return res.status(403).json({error:"O pagamento ainda não foi confirmado pelo ADM."});
  res.json({orderId:o.id,eventName:o.eventName,customer:o.customer,tickets:o.tickets,confirmedAt:o.confirmedAt,ticketCode:o.ticketCode,ticketQrCodeDataUrl:o.ticketQrCodeDataUrl});
});

app.use((err,req,res,next)=>res.status(400).json({error:err.message||"Erro no servidor."}));
app.use(express.static(path.join(ROOT,"public"),{maxAge:IS_PROD?"1h":0}));
app.get("*",(_,res)=>res.sendFile(path.join(ROOT,"public","index.html")));

app.listen(PORT,"0.0.0.0",()=>console.log(`PARTIU online na porta ${PORT}`));
