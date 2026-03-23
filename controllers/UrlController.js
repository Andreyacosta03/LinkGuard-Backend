import UrlModel from "../model/UrlModel.js";
import validateUrl from "../ZodLink.js";

export default class LinkController {
  static async createLink(req, res) {
    try {
      const { url } = req.body;
      const validationResult = await validateUrl({ url });
      if (!validationResult.success) {
        return res.status(400).json({ error: "URL no válida" });
      }

      const urlCheckResult = await UrlModel.checkUrl(url);
      if (urlCheckResult.error) {
        return res.status(urlCheckResult.status || 500).json(urlCheckResult);
      }
      return res.status(200).json(urlCheckResult);
    } catch (error) {
      return res.status(500).json({ error: "Error interno del servidor" });
    }
  }
}
