import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { checkPassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token";
import crypto from "crypto";
import { rmSync } from "fs";
import { OAuth2Client } from "google-auth-library";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !clientSecret) {
    throw new Error("Google client id and secret both are missing");
  }

  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri,
  });
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "invalid data!",
        errors: result.error.flatten(),
      });
    }

    const { email, password, name } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(409).json({
        message: "Email is already in use! Please try with another email",
      });
    }

    const passwordHash = await hashPassword(password);

    const newlyCreatedUser = await User.create({
      name: name,
      passwordHash,
      email: normalizedEmail,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    // email verification part
    const verifyToken = jwt.sign(
      {
        sub: newlyCreatedUser.id,
      },
      process.env.JWT_ACCESS_SECRET!,
      { expiresIn: "1d" }
    );

    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newlyCreatedUser.email,
      "Verify your email",
      `
        <p>Please verify your email by clicking this link: </p>
        <p><a href="${verifyUrl}">${verifyUrl}</a></p>
        `
    );

    return res.status(201).json({
      message: "User registered",
      user: {
        id: newlyCreatedUser.id,
        email: newlyCreatedUser.email,
        role: newlyCreatedUser.role,
        isEmailVerified: newlyCreatedUser.isEmailVerified,
        name,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string | undefined;

  if (!token) {
    return res.status(400).json({
      message: "Verification token is missing",
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
    };

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }

    if (user.isEmailVerified) {
      return res.json({ message: "Email is already verified" });
    }

    user.isEmailVerified = true;

    await user.save();

    return res.json({
      message: "Email is now verified! You can login",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "invalid data!",
        errors: result.error.flatten(),
      });
    }

    const { email, password } = req.body;

    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const ok = await checkPassword(password, user.passwordHash);

    if (!ok) {
      return res.status(400).json({ message: "Invalid password" });
    }

    if (!user.isEmailVerified) {
      return res
        .status(403)
        .json({ message: "Please verify your email before logging in" });
    }

    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Login successfully done",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function refreshHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken as string | undefined;

    if (!token) {
      return res.status(401).json({ message: "Refresh token missing" });
    }

    const payload = verifyRefreshToken(token);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(401).json({ message: "User not found!" });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "Refresh token invalidated!" });
    }

    const newAccessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );

    const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Token refreshed",
      accessToken: newAccessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function logoutHandler(_req: Request, res: Response) {
  res.clearCookie("refreshToken", { path: "/" });

  return res.status(200).json({
    message: "Logged out",
  });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  const { email } = req.body as { email?: string };

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.json({
        message:
          "If an account with this email exists, we will send you a reset link",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");

    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    // Initialize reset password token
    user.resetPasswordToken = tokenHash;
    // Create a expired time reset password
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000); //15 Minutes

    await user.save();

    const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      user.email,
      "Reset your password",
      `
      <p>You requested password reset. Click on the below link to reset the password</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
      `
    );

    return res.json({
      message:
        "If an account with this email exists, we will send you a reset link",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  const { token, password } = req.body as { token?: string; password?: string };

  if (!token) {
    return res.status(400).json({ message: "Reset token is missing" });
  }

  if (!password || password.length < 6) {
    return res
      .status(400)
      .json({ message: "Password must be at least 6 characters long" });
  }

  try {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    const newPasswordHash = await hashPassword(password);
    user.passwordHash = newPasswordHash;

    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    user.tokenVersion = user.tokenVersion + 1;

    await user.save();

    return res.json({
      message: "Password reset successfully",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function googleAuthStartHandler(_req: Request, res: Response) {
  try {
    const client = getGoogleClient();

    const url = client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
    });

    res.redirect(url);
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function googelAuthCallback(req: Request, res: Response) {
  const code = req.query.code as string | undefined;

  if (!code) {
    return res.status(400).json({
      message: "Missing code in callback",
    });
  }

  try {
    const client = getGoogleClient();

    const { tokens } = await client.getToken(code);

    if (!tokens.id_token) {
      return res.status(400).json({
        message: "No googles id_token is present",
      });
    }

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID as string,
    });

    const payload = ticket.getPayload();

    const email = payload?.email;
    const emailVerified = payload?.email_verified;

    if (!email || !emailVerified) {
      return res.status(400).json({
        message: "Google email account is not verified",
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const passwordHash = await hashPassword(randomPassword);

      user = await User.create({
        email: normalizedEmail,
        passwordHash,
        role: "user",
        isEmailVerified: true,
        twoFactorEnabled: false,
      });
    } else {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }
    }

    const accessToken = createAccessToken(
      user.id,
      user.role as "user" | "admin",
      user.tokenVersion
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      message: "Google login successfully",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });

    // console.log("Code: ", code, "Tokens: ", tokens);
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}
