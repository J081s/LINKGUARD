import { getConnectionStatus } from "../backend/services.js";

export default function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();

  return res.status(200).json({
    success: true,
    application: "LinkGuard",
    backend: "Online",
    providers: getConnectionStatus(process.env)
  });
}
