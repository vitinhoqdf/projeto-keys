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
app.use(["/validar", "/license/v1"], limiter);

function checarAdmin(req, res, next) {
    if (!ADMIN_TOKEN || req.headers.authorization !== ADMIN_TOKEN) return res.sendStatus(401);
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

function validarLicenca(key, deviceId, podeVincular) {
    const db = carregar();
    const row = Object.hasOwn(db, key) ? db[key] : null;
    if (!row) return { detail: "key_not_found" };
    if (row.banned) return { detail: "key_banned" };

    const agora = Date.now();
    if (!row.deviceId) {
        if (!podeVincular) return { detail: "key_unavailable" };
        const expiresAt = agora + row.duracaoDias * 86400000;
        if (!Number.isFinite(expiresAt) || expiresAt <= agora) return { detail: "key_expired" };
        db[key] = { ...row, deviceId, expiresAt };
        salvar(db);
        return { expiresAt };
    } else if (row.deviceId !== deviceId) {
        return { detail: "device_mismatch" };
    }

    if (!Number.isFinite(row.expiresAt) || row.expiresAt <= agora) return { detail: "key_expired" };
    return { expiresAt: row.expiresAt };
}

const errosLicenca = {
    key_not_found: { status: 404, msg: "Key inválida" },
    key_banned: { status: 403, msg: "Key inválida" },
    key_unavailable: { status: 403 },
    device_mismatch: { status: 403, msg: "Key já em uso em outro aparelho" },
    key_expired: { status: 403, msg: "Key expirada" },
};

app.post("/validar", (req, res) => {
    const { key, deviceId } = req.body ?? {};
    if (!key || !deviceId) return res.json({ ok: false, msg: "Dados incompletos" });

    const { detail, expiresAt } = validarLicenca(key, deviceId, true);
    if (detail) return res.json({ ok: false, msg: errosLicenca[detail].msg });
    res.json({ ok: true, expira: expiresAt });
});

app.post(["/license/v1/activate", "/license/v1/check"], (req, res) => {
    const token = Buffer.from(req.get("X-API-Token") ?? "");
    const esperado = Buffer.from(LICENSE_API_TOKEN ?? "");
    if (!esperado.length || token.length !== esperado.length || !crypto.timingSafeEqual(token, esperado)) {
        return res.status(401).json({ detail: "unauthorized" });
    }

    const { key, device_id: deviceId, app_id: appId } = req.body ?? {};
    if (![key, deviceId, appId].every(value => typeof value === "string" && value.trim())) {
        return res.status(400).json({ detail: "key_unavailable" });
    }

    const { detail, expiresAt } = validarLicenca(key, deviceId, /^\/license\/v1\/activate\/?$/i.test(req.path));
    if (detail) return res.status(errosLicenca[detail].status).json({ detail });
    const remainingSeconds = (expiresAt - Date.now()) / 1000;
    if (remainingSeconds <= 0) return res.status(403).json({ detail: "key_expired" });
    res.json({ valid: true, remaining_seconds: remainingSeconds });
});

if (require.main === module) {
    app.listen(process.env.PORT || 3000, () => console.log("Servidor no ar"));
}

module.exports = app;
