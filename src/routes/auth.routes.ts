import { Router } from "express";
import {
  loginHandler,
  registerHandler,
  verifyEmailHandler,
  refreshHandler,
  logoutHandler,
  forgotPasswordHandler,
  resetPasswordHandler,
  googleAuthStartHandler,
  googelAuthCallback,
} from "../controllers/auth/auth.controller";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh", refreshHandler);
router.post("/logout", logoutHandler);
router.post("/forgot-password", forgotPasswordHandler);
router.post("/reset-password", resetPasswordHandler);
router.get("/google", googleAuthStartHandler);
router.get("/google/callback", googelAuthCallback);

export default router;
