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
const LICENSE_API_TOKEN = process.env.LICENSE_API_TOKEN;

const limiter = rateLimit({ windowMs: 60 * 1000, max: 10 });
app.use("/validar", limiter);
app.use("/license/v1", limiter);

function checarAdmin(req, res, next) {
    if (req.headers.authorization !== ADMIN_TOKEN) return res.sendStatus(401);
    next();
}

app.post("/admin/gerar", checarAdmin, (req, res) => {
    const dias = req.body.dias || 30;
    const prefixo = req.body.prefixo;
    const parteAleatoria = crypto.randomBytes(4).toString("hex").toUpperCase().match(/.{4}/g).join("-");
    const key = prefixo ? `${prefixo}-${parteAleatoria}` : parteAleatoria;
    const db = carregar();
    db[key] = { deviceId: null, duracaoDias: dias, expiresAt: null, banned: false };
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
    db[req.body.key].expiresAt = null;
    salvar(db);
    res.json({ ok: true });
});

function validarLicenca(key, deviceId, ativar) {
    const db = carregar();
    if (!Object.hasOwn(db, key)) return { detail: "key_not_found" };
    const row = db[key];
    if (!row) return { detail: "key_not_found" };
    if (row.banned) return { detail: "key_banned" };

    const agora = Date.now();
    if (!row.deviceId) {
        if (!ativar) return { detail: "key_unavailable" };
        const expira = agora + row.duracaoDias * 86400000;
        if (!Number.isFinite(expira) || expira <= agora) return { detail: "key_expired" };
        row.deviceId = deviceId;
        row.expiresAt = expira;
        salvar(db);
    } else if (row.deviceId !== deviceId) {
        return { detail: "device_mismatch" };
    }

    if (!Number.isFinite(row.expiresAt) || row.expiresAt <= agora) return { detail: "key_expired" };
    return { expira: row.expiresAt, remaining_seconds: (row.expiresAt - agora) / 1000 };
}

const mensagensValidar = {
    key_not_found: "Key inválida",
    key_banned: "Key inválida",
    device_mismatch: "Key já em uso em outro aparelho",
    key_expired: "Key expirada",
    key_unavailable: "Key inválida",
};

app.post("/validar", (req, res) => {
    const { key, deviceId } = req.body || {};
    if (typeof key !== "string" || !key || typeof deviceId !== "string" || !deviceId) {
        return res.json({ ok: false, msg: "Dados incompletos" });
    }
    const resultado = validarLicenca(key, deviceId, true);
    if (resultado.detail) return res.json({ ok: false, msg: mensagensValidar[resultado.detail] });
    res.json({ ok: true, expira: resultado.expira });
});

function responderIPA(ativar) {
    const esperado = Buffer.from(LICENSE_API_TOKEN ?? "");
    return (req, res) => {
        const token = Buffer.from(req.get("X-API-Token") ?? "");
        if (!esperado.length || token.length !== esperado.length || !crypto.timingSafeEqual(token, esperado)) {
            return res.status(401).json({ detail: "unauthorized" });
        }
        const { key, device_id: deviceId, app_id: appId } = req.body ?? {};
        if (![key, deviceId, appId].every(value => typeof value === "string" && value.trim())) {
            return res.status(400).json({ detail: "key_unavailable" });
        }
        const resultado = validarLicenca(key, deviceId, ativar);
        if (resultado.detail) {
            return res.status(resultado.detail === "key_not_found" ? 404 : 403)
                .json({ detail: resultado.detail });
        }
        res.json({ valid: true, remaining_seconds: resultado.remaining_seconds });
    };
}

app.post("/license/v1/activate", responderIPA(true));
app.post("/license/v1/check", responderIPA(false));

if (require.main === module) {
    app.listen(process.env.PORT || 3000, () => console.log("Servidor no ar"));
}

module.exports = app;
