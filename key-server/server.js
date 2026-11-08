const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const rateLimit = require("express-rate-limit");

const DB_FILE = process.env.DB_PATH || "./keys.json";

function carregar() {
    if (!fs.existsSync(DB_FILE)) return {};
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
function salvar(db) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

const limiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
app.use("/validar", limiter);

function checarAdmin(req, res, next) {
    if (req.headers.authorization !== ADMIN_TOKEN) return res.sendStatus(401);
    next();
}

app.post("/admin/gerar", checarAdmin, (req, res) => {
    const dias = req.body.dias || 30;
    const key = crypto.randomBytes(8).toString("hex").toUpperCase().match(/.{4}/g).join("-");
    const db = carregar();
    db[key] = { deviceId: null, expiresAt: Date.now() + dias * 86400000, banned: false };
    salvar(db);
    res.json({ key });
});

app.post("/admin/banir", checarAdmin, (req, res) => {
    const db = carregar();
    if (!db[req.body.key]) return res.json({ ok: false });
    db[req.body.key].banned = true;
    salvar(db);
    res.json({ ok: true });
});

app.post("/admin/resetar", checarAdmin, (req, res) => {
    const db = carregar();
    if (!db[req.body.key]) return res.json({ ok: false });
    db[req.body.key].deviceId = null;
    salvar(db);
    res.json({ ok: true });
});

app.post("/validar", (req, res) => {
    const { key, deviceId } = req.body;
    if (!key || !deviceId) return res.json({ ok: false, msg: "Dados incompletos" });

    const db = carregar();
    const row = db[key];
    if (!row || row.banned) return res.json({ ok: false, msg: "Key inválida" });
    if (row.expiresAt < Date.now()) return res.json({ ok: false, msg: "Key expirada" });

    if (!row.deviceId) {
        row.deviceId = deviceId;
        salvar(db);
    } else if (row.deviceId !== deviceId) {
        return res.json({ ok: false, msg: "Key já em uso em outro aparelho" });
    }
    res.json({ ok: true, expira: row.expiresAt });
});

app.listen(process.env.PORT || 3000, () => console.log("Servidor no ar"));