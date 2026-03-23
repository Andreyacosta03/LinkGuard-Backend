import Router from "express";
import UrlController from "../controllers/UrlController.js";

const router = Router();
router.post("/", UrlController.createLink);
export default router;
