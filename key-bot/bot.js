require("dotenv").config({ override: true });

const TelegramBot = require("node-telegram-bot-api");
const fetch = require("node-fetch");

const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const SERVER = process.env.SERVER_URL;
const ADMINS = (process.env.ADMINS || "").split(",").map(s => s.trim());

const bot = new TelegramBot(BOT_TOKEN, { polling: true });

bot.onText(/\/gerar (\d+)/, async (msg, match) => {
    if (!ADMINS.includes(String(msg.from.id))) return;
    const dias = match[1];
    const r = await fetch(`${SERVER}/admin/gerar`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: ADMIN_TOKEN },
        body: JSON.stringify({ dias: Number(dias) }),
    });
    const data = await r.json();
    bot.sendMessage(msg.chat.id, `✅ Key gerada (${dias} dias):\n\`${data.key}\``, { parse_mode: "Markdown" });
});

bot.onText(/\/banir (.+)/, async (msg, match) => {
    if (!ADMINS.includes(String(msg.from.id))) return;
    const r = await fetch(`${SERVER}/admin/banir`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: ADMIN_TOKEN },
        body: JSON.stringify({ key: match[1].trim() }),
    });
    const data = await r.json();
    bot.sendMessage(msg.chat.id, data.ok ? "🚫 Key banida." : "❌ Key não encontrada.");
});

bot.onText(/\/resetar (.+)/, async (msg, match) => {
    if (!ADMINS.includes(String(msg.from.id))) return;
    const r = await fetch(`${SERVER}/admin/resetar`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: ADMIN_TOKEN },
        body: JSON.stringify({ key: match[1].trim() }),
    });
    const data = await r.json();
    bot.sendMessage(msg.chat.id, data.ok ? "🔄 Dispositivo da key resetado." : "❌ Key não encontrada.");
});

console.log("Bot rodando...");