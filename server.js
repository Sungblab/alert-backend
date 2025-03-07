const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const webpush = require("web-push");
require("dotenv").config();

// Express 앱 초기화
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";
const REFRESH_TOKEN_SECRET =
  process.env.REFRESH_TOKEN_SECRET || "your_refresh_token_secret_key";
const ACCESS_TOKEN_EXPIRES_IN = "15m"; // 액세스 토큰 만료 시간
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRY || "7d"; // 리프레시 토큰 만료 시간

// 미들웨어 설정
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB 연결 설정
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/alert-project";
mongoose.connect(MONGODB_URI);

// 이메일 전송을 위한 Nodemailer 설정
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // TLS 사용
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
  tls: {
    rejectUnauthorized: false, // 인증서 검증 비활성화 (개발 환경용)
  },
  connectionTimeout: 10000, // 연결 타임아웃 10초
  greetingTimeout: 10000, // 인사 타임아웃 10초
  socketTimeout: 10000, // 소켓 타임아웃 10초
});

// 이메일 전송 테스트
transporter.verify(function (error, success) {
  if (error) {
    console.error("SMTP 서버 연결 오류:", error);
  }
});

// 환경변수에 NEIS API 키 추가
const NEIS_API_KEY = process.env.NEIS_API_KEY;
const SCHOOL_CODE = "8490065";
const OFFICE_CODE = "Q10";

// VAPID 키 설정
const VAPID_PUBLIC_KEY =
  process.env.VAPID_PUBLIC_KEY ||
  "BLBx-hf2WrL2qEa0qKb-aCJbcxEvyn-Sy_3AXpgQwgEfJE2rjBYuXmYIcMzlL_o9m4ECVS57WZLJ0MBRSvuCcTk";
const VAPID_PRIVATE_KEY =
  process.env.VAPID_PRIVATE_KEY ||
  "3KzvKasA2e_4Yg_TQ5l9rRRK4jqDuNMcYZXEg2Vc1nc";
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || "mailto:admin@example.com";

webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

// 한국 시간 유틸리티 함수 (타임존 사용)
const getKoreanTime = () => {
  const now = new Date();
  return new Date(now.toLocaleString("en-US", { timeZone: "Asia/Seoul" }));
};

const formatKoreanDate = (date) => {
  // 타임존을 'Asia/Seoul'로 설정하여 한국 시간으로 변환
  const koreanTime = new Date(
    date.toLocaleString("en-US", { timeZone: "Asia/Seoul" })
  );

  // YYYY-MM-DD HH:MM:SS 형식으로 변환
  const year = koreanTime.getFullYear();
  const month = String(koreanTime.getMonth() + 1).padStart(2, "0");
  const day = String(koreanTime.getDate()).padStart(2, "0");
  const hours = String(koreanTime.getHours()).padStart(2, "0");
  const minutes = String(koreanTime.getMinutes()).padStart(2, "0");
  const seconds = String(koreanTime.getSeconds()).padStart(2, "0");

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
};

// 날짜만 반환하는 함수 (YYYY-MM-DD)
const formatKoreanDateOnly = (date) => {
  return formatKoreanDate(date).split(" ")[0];
};

// 시간만 반환하는 함수 (HH:MM:SS)
const formatKoreanTimeOnly = (date) => {
  return formatKoreanDate(date).split(" ")[1];
};

// 기본 라우트
app.get("/", (req, res) => {
  res.send("수행평가 알리미 API 서버가 실행 중입니다.");
});

// 사용자 스키마 정의
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    school: { type: String, required: true },
    grade: { type: String, required: true },
    class: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    isAdmin: { type: Boolean, default: false },
    pushSubscription: { type: Object, default: null },
    refreshToken: { type: String, default: null }, // 리프레시 토큰 필드 추가
  },
  { timestamps: true }
);

// 이메일 인증 코드 스키마 정의
const verificationSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  createdAt: { type: String, default: () => formatKoreanDate(new Date()) },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 600000),
    expires: 600,
  }, // 10분 후 자동 삭제
});

// 학교 스키마 정의
const schoolSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  address: { type: String },
  description: { type: String },
  createdAt: { type: String, default: () => formatKoreanDate(new Date()) },
});

// 사용자 모델 생성
const User = mongoose.model("User", userSchema);

// 이메일 인증 모델 생성
const Verification = mongoose.model("Verification", verificationSchema);

// 학교 모델 생성
const School = mongoose.model("School", schoolSchema);

// 알림 스키마 정의
const alertSchema = new mongoose.Schema({
  title: { type: String, required: true },
  date: { type: String, required: true },
  description: { type: String, required: true },
  notify: { type: Boolean, default: false },
  school: { type: String, required: true },
  grade: { type: String, required: true },
  class: { type: String, required: true },
  createdAt: { type: String, default: () => formatKoreanDate(new Date()) },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  authorName: { type: String },
  isAnonymous: { type: Boolean, default: false },
});

const Alert = mongoose.model("Alert", alertSchema);

// 팁 게시판 스키마 정의
const tipSchema = new mongoose.Schema({
  content: { type: String, required: true },
  school: { type: String, required: true },
  grade: { type: String, required: true },
  class: { type: String, required: true },
  authorName: { type: String, default: "익명" },
  likes: { type: Number, default: 0 },
  createdAt: { type: String, default: () => formatKoreanDate(new Date()) },
  ipAddress: { type: String, required: true },
});

// 팁 댓글 스키마 정의
const tipCommentSchema = new mongoose.Schema({
  tipId: { type: mongoose.Schema.Types.ObjectId, ref: "Tip", required: true },
  content: { type: String, required: true },
  authorName: { type: String, default: "익명" },
  parentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "TipComment",
    default: null,
  },
  createdAt: { type: String, default: () => formatKoreanDate(new Date()) },
  ipAddress: { type: String, required: true },
});

const Tip = mongoose.model("Tip", tipSchema);
const TipComment = mongoose.model("TipComment", tipCommentSchema);

// 인증 미들웨어
const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({ message: "인증이 필요합니다." });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.id);

      if (!user) {
        return res.status(401).json({ message: "유효하지 않은 인증입니다." });
      }

      req.user = user;
      next();
    } catch (error) {
      // 토큰이 만료되었거나 유효하지 않은 경우
      if (error.name === "TokenExpiredError") {
        return res.status(401).json({
          message: "토큰이 만료되었습니다.",
          expired: true,
        });
      }
      throw error;
    }
  } catch (error) {
    console.error("인증 오류:", error);
    res.status(401).json({ message: "인증에 실패했습니다." });
  }
};

// 관리자 인증 미들웨어
const adminAuth = async (req, res, next) => {
  try {
    console.log("adminAuth 미들웨어 시작");
    console.log("요청 헤더:", req.headers);

    const authHeader = req.headers.authorization;
    if (!authHeader) {
      console.error("인증 오류: Authorization 헤더가 없음");
      return res.status(401).json({ message: "인증이 필요합니다." });
    }

    console.log("Authorization 헤더:", authHeader);
    const token = authHeader.split(" ")[1];
    console.log("추출된 토큰:", token);

    if (!token) {
      console.error("인증 오류: 토큰이 없음");
      return res.status(401).json({ message: "인증이 필요합니다." });
    }

    try {
      console.log("토큰 검증 시작");
      console.log("JWT_SECRET:", JWT_SECRET);
      const decoded = jwt.verify(token, JWT_SECRET);
      console.log("디코딩된 토큰:", decoded);

      const user = await User.findById(decoded.id);
      console.log(
        "찾은 사용자:",
        user
          ? {
              id: user._id,
              name: user.name,
              email: user.email,
              isAdmin: user.isAdmin,
            }
          : "없음"
      );

      if (!user) {
        console.error("인증 오류: 사용자를 찾을 수 없음");
        return res.status(401).json({ message: "인증이 필요합니다." });
      }

      if (!user.isAdmin) {
        console.error("인증 오류: 관리자 권한 없음");
        return res.status(403).json({ message: "관리자 권한이 필요합니다." });
      }

      req.user = user;
      next();
    } catch (error) {
      console.error("토큰 검증 오류:", error);
      if (error.name === "TokenExpiredError") {
        return res.status(401).json({ message: "토큰이 만료되었습니다." });
      }
      if (error.name === "JsonWebTokenError") {
        return res.status(401).json({ message: "유효하지 않은 토큰입니다." });
      }
      return res.status(401).json({ message: "인증이 필요합니다." });
    }
  } catch (error) {
    console.error("인증 오류:", error);
    return res.status(401).json({ message: "인증이 필요합니다." });
  }
};

// 이메일 인증 코드 생성 및 전송
app.post("/api/users/send-verification", async (req, res) => {
  try {
    const { email } = req.body;

    // 이메일 형식 검증
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res
        .status(400)
        .json({ message: "유효한 이메일 주소를 입력해주세요." });
    }

    // 이미 가입된 이메일인지 확인
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "이미 등록된 이메일입니다." });
    }

    // 6자리 인증 코드 생성
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    // 이전 인증 코드 삭제
    await Verification.deleteMany({ email });

    // 새 인증 코드 저장
    const verification = new Verification({
      email,
      code: verificationCode,
    });

    await verification.save();

    // 이메일 전송
    const mailOptions = {
      from: `"${process.env.EMAILS_FROM_NAME}" <${process.env.EMAILS_FROM_EMAIL}>`,
      to: email,
      subject: "수행평가 알리미 - 이메일 인증 코드",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #4F46E5;">수행평가 알리미 - 이메일 인증</h2>
          <p>안녕하세요! 수행평가 알리미 서비스에 가입해 주셔서 감사합니다.</p>
          <p>아래의 인증 코드를 입력하여 이메일 인증을 완료해 주세요:</p>
          <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
            ${verificationCode}
          </div>
          <p>이 인증 코드는 10분 동안 유효합니다.</p>
          <p>본인이 요청하지 않았다면 이 이메일을 무시하셔도 됩니다.</p>
          <p style="margin-top: 30px; font-size: 12px; color: #666;">
            &copy; 2025 수행평가 알리미. All rights reserved.
          </p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: "인증 코드가 이메일로 전송되었습니다." });
  } catch (error) {
    console.error("이메일 인증 코드 전송 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 이메일 인증 코드 확인
app.post("/api/users/verify-email", async (req, res) => {
  try {
    const { email, code } = req.body;

    // 인증 코드 확인
    const verification = await Verification.findOne({ email, code });

    if (!verification) {
      return res
        .status(400)
        .json({ message: "인증 코드가 유효하지 않거나 만료되었습니다." });
    }

    // 인증 성공
    await Verification.deleteOne({ email, code });

    res.json({ verified: true, message: "이메일 인증이 완료되었습니다." });
  } catch (error) {
    console.error("이메일 인증 확인 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 로그인
app.post("/api/users/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 사용자 확인
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
    }

    // 비밀번호 확인
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
    }

    // 액세스 토큰 생성
    const accessToken = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: ACCESS_TOKEN_EXPIRES_IN,
    });

    // 리프레시 토큰 생성
    const refreshToken = jwt.sign({ id: user._id }, REFRESH_TOKEN_SECRET, {
      expiresIn: REFRESH_TOKEN_EXPIRES_IN,
    });

    // 리프레시 토큰을 사용자 정보에 저장
    user.refreshToken = refreshToken;
    await user.save();

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        school: user.school,
        grade: user.grade,
        class: user.class,
      },
    });
  } catch (error) {
    console.error("로그인 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 토큰 갱신 엔드포인트 추가
app.post("/api/users/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: "리프레시 토큰이 필요합니다." });
    }

    // 리프레시 토큰 검증
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);

    // 사용자 찾기
    const user = await User.findById(decoded.id);

    if (!user || user.refreshToken !== refreshToken) {
      return res
        .status(401)
        .json({ message: "유효하지 않은 리프레시 토큰입니다." });
    }

    // 새 액세스 토큰 발급
    const newAccessToken = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: ACCESS_TOKEN_EXPIRES_IN,
    });

    res.json({
      accessToken: newAccessToken,
    });
  } catch (error) {
    console.error("토큰 갱신 오류:", error);

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "리프레시 토큰이 만료되었습니다. 다시 로그인해주세요.",
      });
    }

    res.status(401).json({ message: "유효하지 않은 리프레시 토큰입니다." });
  }
});

// 로그아웃 엔드포인트 추가
app.post("/api/users/logout", auth, async (req, res) => {
  try {
    // 사용자의 리프레시 토큰 제거
    req.user.refreshToken = null;
    await req.user.save();

    res.json({ message: "로그아웃되었습니다." });
  } catch (error) {
    console.error("로그아웃 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 사용자 계정 정보 업데이트
app.put("/api/users/account", auth, async (req, res) => {
  try {
    const {
      email,
      password,
      school,
      grade,
      class: className,
      weeklySummary,
    } = req.body;
    const user = req.user;

    console.log("계정 정보 업데이트 요청:", {
      email,
      school,
      grade,
      class: className,
      weeklySummary,
    });

    // 이메일 변경 시 중복 확인
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res
          .status(400)
          .json({ message: "이미 사용 중인 이메일입니다." });
      }
      user.email = email;
    }

    // 비밀번호 변경
    if (password) {
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
    }

    // 학교 정보 업데이트
    if (school) user.school = school;
    if (grade) user.grade = grade;
    if (className) user.class = className;

    // 주간 요약 설정 업데이트
    if (weeklySummary !== undefined) {
      user.weeklySummary = weeklySummary;
    }

    await user.save();

    // 비밀번호 제외하고 응답
    const userResponse = user.toObject();
    delete userResponse.password;

    res.json({
      message: "계정 정보가 업데이트되었습니다.",
      user: userResponse,
    });
  } catch (error) {
    console.error("계정 정보 업데이트 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 현재 로그인한 사용자 정보 조회
app.get("/api/users/me", auth, async (req, res) => {
  try {
    // 비밀번호 제외하고 응답
    const userResponse = req.user.toObject();
    delete userResponse.password;

    res.json(userResponse);
  } catch (error) {
    console.error("사용자 정보 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 사용자 계정 삭제 (본인)
app.delete("/api/users/account", auth, async (req, res) => {
  try {
    const user = req.user;

    // 사용자 관련 데이터 삭제 (알림 등)
    await Alert.deleteMany({ userId: user._id });

    // 사용자 계정 삭제
    await User.findByIdAndDelete(user._id);

    res.json({ message: "계정이 성공적으로 삭제되었습니다." });
  } catch (error) {
    console.error("계정 삭제 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 알림 API 라우트
// 모든 알림 가져오기
app.get("/api/alerts", async (req, res) => {
  try {
    const { school, grade, class: className } = req.query;

    // 필터 조건 구성
    const filter = {};
    if (school) filter.school = school;
    if (grade) filter.grade = grade;
    if (className) filter.class = className;

    const alerts = await Alert.find(filter).sort({ date: 1 });
    res.json(alerts);
  } catch (error) {
    console.error("알림 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 단일 알림 가져오기
app.get("/api/alerts/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const alert = await Alert.findById(id);

    if (!alert) {
      return res.status(404).json({ message: "알림을 찾을 수 없습니다." });
    }

    res.json(alert);
  } catch (error) {
    console.error("알림 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 새 알림 생성
app.post("/api/alerts", async (req, res) => {
  try {
    const {
      title,
      date,
      description,
      notify,
      school,
      grade,
      class: className,
      isAnonymous,
      authorName,
    } = req.body;

    // 날짜가 Date 객체로 전달된 경우 한국 시간 문자열로 변환
    let formattedDate = date;
    if (date instanceof Date) {
      formattedDate = formatKoreanDateOnly(date); // YYYY-MM-DD 형식
    }

    // 익명 사용자를 위한 귀여운 이름 생성
    const anonymousNames = [
      "깜찍한 판다",
      "행복한 코알라",
      "귀여운 토끼",
      "멋진 고양이",
      "똑똑한 여우",
      "용감한 호랑이",
      "신비한 유니콘",
      "친절한 강아지",
      "재빠른 다람쥐",
      "느긋한 나무늘보",
      "활기찬 펭귄",
      "지혜로운 부엉이",
      "장난꾸러기 원숭이",
      "우아한 기린",
      "따뜻한 알파카",
      "꿈꾸는 고래",
      "춤추는 돌고래",
      "웃는 하마",
      "수줍은 판다",
      "호기심 많은 여우",
    ];

    // 작성자 이름 설정 (익명이면 랜덤 이름, 아니면 지정된 이름)
    let finalAuthorName;
    let finalIsAnonymous = isAnonymous !== false; // 기본값은 익명

    if (finalIsAnonymous) {
      finalAuthorName =
        anonymousNames[Math.floor(Math.random() * anonymousNames.length)];
    } else {
      finalAuthorName = authorName || "익명";
    }

    const newAlert = new Alert({
      title,
      date: formattedDate,
      description,
      notify,
      school,
      grade,
      class: className,
      authorName: finalAuthorName,
      isAnonymous: finalIsAnonymous,
    });

    const savedAlert = await newAlert.save();
    res.status(201).json(savedAlert);
  } catch (error) {
    console.error("알림 생성 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 알림 수정
app.put("/api/alerts/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      title,
      date,
      description,
      notify,
      school,
      grade,
      class: className,
      isAnonymous,
      authorName,
    } = req.body;

    // 날짜가 Date 객체로 전달된 경우 한국 시간 문자열로 변환
    let formattedDate = date;
    if (date instanceof Date) {
      formattedDate = formatKoreanDateOnly(date); // YYYY-MM-DD 형식
    }

    // 알림 존재 여부 확인
    const alert = await Alert.findById(id);
    if (!alert) {
      return res.status(404).json({ message: "알림을 찾을 수 없습니다." });
    }

    // 작성자 정보 처리
    let updateData = {
      title,
      date: formattedDate,
      description,
      notify,
      school,
      grade,
      class: className,
    };

    // 작성자 정보가 변경된 경우에만 업데이트
    if (isAnonymous !== undefined) {
      // 익명 여부 업데이트
      updateData.isAnonymous = isAnonymous;

      // 익명이 아니고 작성자 이름이 제공된 경우
      if (!isAnonymous && authorName) {
        updateData.authorName = authorName;
      }
      // 익명으로 변경되었지만 기존에 익명이 아니었던 경우, 랜덤 이름 생성
      else if (isAnonymous && !alert.isAnonymous) {
        const anonymousNames = [
          "깜찍한 판다",
          "행복한 코알라",
          "귀여운 토끼",
          "멋진 고양이",
          "똑똑한 여우",
          "용감한 호랑이",
          "신비한 유니콘",
          "친절한 강아지",
          "재빠른 다람쥐",
          "느긋한 나무늘보",
          "활기찬 펭귄",
          "지혜로운 부엉이",
          "장난꾸러기 원숭이",
          "우아한 기린",
          "따뜻한 알파카",
          "꿈꾸는 고래",
          "춤추는 돌고래",
          "웃는 하마",
          "수줍은 판다",
          "호기심 많은 여우",
        ];
        updateData.authorName =
          anonymousNames[Math.floor(Math.random() * anonymousNames.length)];
      }
    }

    const updatedAlert = await Alert.findByIdAndUpdate(id, updateData, {
      new: true,
    });

    res.json(updatedAlert);
  } catch (error) {
    console.error("알림 수정 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 알림 삭제
app.delete("/api/alerts/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // 알림 존재 여부 확인
    const alert = await Alert.findById(id);
    if (!alert) {
      return res.status(404).json({ message: "알림을 찾을 수 없습니다." });
    }

    const deletedAlert = await Alert.findByIdAndDelete(id);

    res.json({ message: "알림이 삭제되었습니다." });
  } catch (error) {
    console.error("알림 삭제 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 학교 관리 API 엔드포인트
// 모든 학교 조회
app.get("/api/schools", async (req, res) => {
  try {
    const schools = await School.find().sort({ createdAt: -1 });
    res.json(schools);
  } catch (error) {
    console.error("학교 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 단일 학교 조회
app.get("/api/schools/:id", async (req, res) => {
  try {
    const school = await School.findById(req.params.id);
    if (!school) {
      return res.status(404).json({ message: "학교를 찾을 수 없습니다." });
    }
    res.json(school);
  } catch (error) {
    console.error("학교 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 학교 추가 (관리자 전용)
app.post("/api/schools", adminAuth, async (req, res) => {
  try {
    const { name, address, description } = req.body;

    // 필수 필드 검증
    if (!name) {
      return res.status(400).json({ message: "학교 이름은 필수 항목입니다." });
    }

    // 중복 학교 확인
    const existingSchool = await School.findOne({ name });
    if (existingSchool) {
      return res.status(400).json({ message: "이미 등록된 학교입니다." });
    }

    const school = new School({
      name,
      address,
      description,
    });

    await school.save();
    res.status(201).json(school);
  } catch (error) {
    console.error("학교 추가 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 학교 수정 (관리자 전용)
app.put("/api/schools/:id", adminAuth, async (req, res) => {
  try {
    const { name, address, description } = req.body;

    // 필수 필드 검증
    if (!name) {
      return res.status(400).json({ message: "학교 이름은 필수 항목입니다." });
    }

    const school = await School.findById(req.params.id);
    if (!school) {
      return res.status(404).json({ message: "학교를 찾을 수 없습니다." });
    }

    // 중복 학교 확인 (다른 학교와 이름이 중복되는지)
    const existingSchool = await School.findOne({
      name,
      _id: { $ne: req.params.id },
    });
    if (existingSchool) {
      return res.status(400).json({ message: "이미 등록된 학교 이름입니다." });
    }

    school.name = name;
    school.address = address;
    school.description = description;

    await school.save();
    res.json(school);
  } catch (error) {
    console.error("학교 수정 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 학교 삭제 (관리자 전용)
app.delete("/api/schools/:id", adminAuth, async (req, res) => {
  try {
    const school = await School.findById(req.params.id);
    if (!school) {
      return res.status(404).json({ message: "학교를 찾을 수 없습니다." });
    }

    await school.deleteOne();
    res.json({ message: "학교가 삭제되었습니다." });
  } catch (error) {
    console.error("학교 삭제 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 사용자 관리 API 엔드포인트 (관리자 전용)
// 모든 사용자 조회
app.get("/api/users", adminAuth, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    console.error("사용자 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 단일 사용자 조회 (관리자 전용)
app.get("/api/users/:id", adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }
    res.json(user);
  } catch (error) {
    console.error("사용자 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 사용자 정보 수정 (관리자 전용)
app.put("/api/users/:id", adminAuth, async (req, res) => {
  try {
    const { name, email, school, grade, class: className, role } = req.body;

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    // 이메일 중복 확인
    if (email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res
          .status(400)
          .json({ message: "이미 사용 중인 이메일입니다." });
      }
    }

    // 필드 업데이트
    if (name) user.name = name;
    if (email) user.email = email;
    if (school) user.school = school;
    if (grade) user.grade = grade;
    if (className) user.class = className;
    if (role && ["user", "admin"].includes(role)) user.role = role;

    await user.save();

    // 비밀번호 제외하고 응답
    const userResponse = user.toObject();
    delete userResponse.password;

    res.json(userResponse);
  } catch (error) {
    console.error("사용자 수정 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 사용자 삭제 (관리자 전용)
app.delete("/api/users/:id", adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    await user.deleteOne();
    res.json({ message: "사용자가 삭제되었습니다." });
  } catch (error) {
    console.error("사용자 삭제 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 관리자 계정 생성 (초기 설정용)
app.post("/api/admin/setup", async (req, res) => {
  try {
    const { name, email, password, secretKey } = req.body;

    // 비밀 키 검증 (실제 환경에서는 환경 변수로 관리)
    const ADMIN_SECRET_KEY =
      process.env.ADMIN_SECRET_KEY || "admin_secret_key_123";
    if (secretKey !== ADMIN_SECRET_KEY) {
      return res
        .status(403)
        .json({ message: "관리자 설정 키가 올바르지 않습니다." });
    }

    // 필수 필드 검증
    if (!name || !email || !password) {
      return res.status(400).json({ message: "모든 필드를 입력해주세요." });
    }

    // 이메일 중복 확인
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "이미 사용 중인 이메일입니다." });
    }

    // 비밀번호 해싱
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 관리자 계정 생성
    const admin = new User({
      name,
      email,
      password: hashedPassword,
      role: "admin",
    });

    await admin.save();

    // 토큰 생성
    const token = jwt.sign({ id: admin._id }, JWT_SECRET, { expiresIn: "7d" });

    // 비밀번호 제외하고 응답
    const adminResponse = admin.toObject();
    delete adminResponse.password;

    res.status(201).json({
      token,
      user: adminResponse,
    });
  } catch (error) {
    console.error("관리자 설정 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 학사일정 조회 API
app.get("/api/schedule", async (req, res) => {
  try {
    const { year, month } = req.query;
    const fromDate = `${year}${String(month).padStart(2, "0")}01`;
    const toDate = `${year}${String(month).padStart(2, "0")}${new Date(
      year,
      month,
      0
    ).getDate()}`;

    const response = await axios.get(
      "https://open.neis.go.kr/hub/SchoolSchedule",
      {
        params: {
          KEY: NEIS_API_KEY,
          Type: "json",
          ATPT_OFCDC_SC_CODE: OFFICE_CODE,
          SD_SCHUL_CODE: SCHOOL_CODE,
          AA_FROM_YMD: fromDate,
          AA_TO_YMD: toDate,
        },
      }
    );

    // NEIS API가 데이터가 없을 때 RESULT 객체를 반환하는 경우 처리
    if (response.data.RESULT?.CODE === "INFO-200") {
      // 데이터가 없는 경우 빈 배열 반환
      return res.json([]);
    }

    const schedules = response.data.SchoolSchedule
      ? response.data.SchoolSchedule[1].row
      : [];

    res.json(schedules);
  } catch (error) {
    console.error("학사일정 조회 중 오류:", error);
    // 오류 발생 시 빈 배열 반환
    res.json([]);
  }
});

// 팁 게시판 API 라우트
// 모든 팁 가져오기
app.get("/api/tips", async (req, res) => {
  try {
    const { school, grade, class: className, limit, _id } = req.query;

    // 필터 조건 구성
    const filter = {};
    if (school) filter.school = school;
    if (grade) filter.grade = grade;
    if (className) filter.class = className;
    if (_id) filter._id = _id;

    // 쿼리 실행
    let query = Tip.find(filter).sort({ createdAt: -1 });

    // 제한이 있는 경우 적용
    if (limit) {
      query = query.limit(parseInt(limit));
    }

    const tips = await query;

    // 각 팁에 대한 댓글 가져오기
    const tipsWithComments = await Promise.all(
      tips.map(async (tip) => {
        const tipObj = tip.toObject();
        const comments = await TipComment.find({ tipId: tip._id }).sort({
          createdAt: 1,
        });
        tipObj.comments = comments;
        return tipObj;
      })
    );

    res.json(tipsWithComments);
  } catch (error) {
    console.error("팁 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 새 팁 작성
app.post("/api/tips", async (req, res) => {
  try {
    const { content, school, grade, class: className, authorName } = req.body;

    // 클라이언트 IP 주소 가져오기
    const ipAddress =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    // 필수 필드 검증
    if (!content) {
      return res.status(400).json({ message: "내용은 필수 항목입니다." });
    }

    // 익명 사용자를 위한 귀여운 이름 생성
    const anonymousNames = [
      "깜찍한 판다",
      "행복한 코알라",
      "귀여운 토끼",
      "멋진 고양이",
      "똑똑한 여우",
      "용감한 호랑이",
      "신비한 유니콘",
      "친절한 강아지",
      "재빠른 다람쥐",
      "느긋한 나무늘보",
      "활기찬 펭귄",
      "지혜로운 부엉이",
      "장난꾸러기 원숭이",
      "우아한 기린",
      "따뜻한 알파카",
      "꿈꾸는 고래",
      "춤추는 돌고래",
      "웃는 하마",
      "수줍은 판다",
      "호기심 많은 여우",
    ];
    const randomName =
      authorName ||
      anonymousNames[Math.floor(Math.random() * anonymousNames.length)];

    const newTip = new Tip({
      content,
      school,
      grade,
      class: className,
      authorName: randomName,
      ipAddress,
    });

    const savedTip = await newTip.save();
    res.status(201).json(savedTip);
  } catch (error) {
    console.error("팁 작성 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 팁 좋아요 증가
app.post("/api/tips/:id/like", async (req, res) => {
  try {
    const { id } = req.params;

    const tip = await Tip.findById(id);
    if (!tip) {
      return res.status(404).json({ message: "팁을 찾을 수 없습니다." });
    }

    tip.likes += 1;
    await tip.save();

    res.json(tip);
  } catch (error) {
    console.error("팁 좋아요 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 팁 삭제
app.delete("/api/tips/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // 클라이언트 IP 주소 가져오기
    const ipAddress =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    const tip = await Tip.findById(id);
    if (!tip) {
      return res.status(404).json({ message: "팁을 찾을 수 없습니다." });
    }

    // 관리자 권한 확인
    const isAdmin =
      req.headers["admin-override"] === "true" && req.headers.authorization;

    if (isAdmin) {
      // 관리자 권한 검증
      try {
        const token = req.headers.authorization.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (!user || user.role !== "admin") {
          return res.status(403).json({ message: "관리자 권한이 필요합니다." });
        }
      } catch (error) {
        return res.status(401).json({ message: "인증에 실패했습니다." });
      }
    } else if (tip.ipAddress !== ipAddress) {
      // 일반 사용자는 자신이 작성한 팁만 삭제 가능
      return res
        .status(403)
        .json({ message: "자신이 작성한 팁만 삭제할 수 있습니다." });
    }

    await Tip.findByIdAndDelete(id);

    // 관련 댓글도 삭제
    await TipComment.deleteMany({ tipId: id });

    res.json({ message: "팁이 삭제되었습니다." });
  } catch (error) {
    console.error("팁 삭제 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 팁 댓글 가져오기
app.get("/api/tips/:tipId/comments", async (req, res) => {
  try {
    const { tipId } = req.params;

    const comments = await TipComment.find({ tipId }).sort({ createdAt: 1 });
    res.json(comments);
  } catch (error) {
    console.error("팁 댓글 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 팁 댓글 작성
app.post("/api/tips/:tipId/comments", async (req, res) => {
  try {
    const { tipId } = req.params;
    const { content, authorName, parentId } = req.body;

    // 클라이언트 IP 주소 가져오기
    const ipAddress =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    // 팁 존재 여부 확인
    const tip = await Tip.findById(tipId);
    if (!tip) {
      return res.status(404).json({ message: "팁을 찾을 수 없습니다." });
    }

    // 필수 필드 검증
    if (!content) {
      return res.status(400).json({ message: "내용은 필수 항목입니다." });
    }

    // 부모 댓글 존재 여부 확인 (있는 경우)
    if (parentId) {
      const parentComment = await TipComment.findById(parentId);
      if (!parentComment) {
        return res
          .status(404)
          .json({ message: "부모 댓글을 찾을 수 없습니다." });
      }
    }

    // 익명 사용자를 위한 귀여운 이름 생성
    const anonymousNames = [
      "깜찍한 판다",
      "행복한 코알라",
      "귀여운 토끼",
      "멋진 고양이",
      "똑똑한 여우",
      "용감한 호랑이",
      "신비한 유니콘",
      "친절한 강아지",
      "재빠른 다람쥐",
      "느긋한 나무늘보",
      "활기찬 펭귄",
      "지혜로운 부엉이",
      "장난꾸러기 원숭이",
      "우아한 기린",
      "따뜻한 알파카",
      "꿈꾸는 고래",
      "춤추는 돌고래",
      "웃는 하마",
      "수줍은 판다",
      "호기심 많은 여우",
    ];
    const randomName =
      authorName ||
      anonymousNames[Math.floor(Math.random() * anonymousNames.length)];

    const newComment = new TipComment({
      tipId,
      content,
      authorName: randomName,
      parentId: parentId || null,
      ipAddress,
    });

    const savedComment = await newComment.save();
    res.status(201).json(savedComment);
  } catch (error) {
    console.error("팁 댓글 작성 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 팁 댓글 삭제
app.delete("/api/tips/comments/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // 클라이언트 IP 주소 가져오기
    const ipAddress =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    const comment = await TipComment.findById(id);
    if (!comment) {
      return res.status(404).json({ message: "댓글을 찾을 수 없습니다." });
    }

    // 관리자 권한 확인
    const isAdmin =
      req.headers["admin-override"] === "true" && req.headers.authorization;

    if (isAdmin) {
      // 관리자 권한 검증
      try {
        const token = req.headers.authorization.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (!user || user.role !== "admin") {
          return res.status(403).json({ message: "관리자 권한이 필요합니다." });
        }
      } catch (error) {
        return res.status(401).json({ message: "인증에 실패했습니다." });
      }
    } else if (comment.ipAddress !== ipAddress) {
      // 일반 사용자는 자신이 작성한 댓글만 삭제 가능
      return res
        .status(403)
        .json({ message: "자신이 작성한 댓글만 삭제할 수 있습니다." });
    }

    // 해당 댓글의 모든 답글 삭제
    await TipComment.deleteMany({ parentId: id });

    // 댓글 삭제
    await TipComment.findByIdAndDelete(id);

    res.json({ message: "댓글이 삭제되었습니다." });
  } catch (error) {
    console.error("팁 댓글 삭제 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 비밀번호 재설정 요청 (이메일 인증 코드 전송)
app.post("/api/users/reset-password-request", async (req, res) => {
  try {
    const { email } = req.body;

    // 이메일 형식 검증
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res
        .status(400)
        .json({ message: "유효한 이메일 주소를 입력해주세요." });
    }

    // 사용자 확인
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "등록되지 않은 이메일입니다." });
    }

    // 6자리 인증 코드 생성
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    // 이전 인증 코드 삭제
    await Verification.deleteMany({ email });

    // 새 인증 코드 저장
    const verification = new Verification({
      email,
      code: verificationCode,
    });

    await verification.save();

    // 이메일 전송
    const mailOptions = {
      from: `"${process.env.EMAILS_FROM_NAME}" <${process.env.EMAILS_FROM_EMAIL}>`,
      to: email,
      subject: "수행평가 알리미 - 비밀번호 재설정 인증 코드",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #4F46E5;">수행평가 알리미 - 비밀번호 재설정</h2>
          <p>안녕하세요! 비밀번호 재설정을 요청하셨습니다.</p>
          <p>아래의 인증 코드를 입력하여 본인 확인을 완료해 주세요:</p>
          <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
            ${verificationCode}
          </div>
          <p>이 인증 코드는 10분 동안 유효합니다.</p>
          <p>본인이 요청하지 않았다면 이 이메일을 무시하셔도 됩니다.</p>
          <p style="margin-top: 30px; font-size: 12px; color: #666;">
            &copy; 2025 수행평가 알리미. All rights reserved.
          </p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: "인증 코드가 이메일로 전송되었습니다." });
  } catch (error) {
    console.error("비밀번호 재설정 요청 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 비밀번호 재설정 (인증 코드 확인 후 비밀번호 변경)
app.post("/api/users/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    // 인증 코드 확인
    const verification = await Verification.findOne({ email, code });
    if (!verification) {
      return res
        .status(400)
        .json({ message: "인증 코드가 유효하지 않거나 만료되었습니다." });
    }

    // 사용자 확인
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    // 비밀번호 복잡성 검증
    const passwordRegex =
      /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        message:
          "비밀번호는 8자 이상이며, 영문, 숫자, 특수문자를 포함해야 합니다.",
      });
    }

    // 비밀번호 해싱
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // 비밀번호 업데이트
    user.password = hashedPassword;
    await user.save();

    // 인증 코드 삭제
    await Verification.deleteOne({ email, code });

    res.json({ message: "비밀번호가 성공적으로 재설정되었습니다." });
  } catch (error) {
    console.error("비밀번호 재설정 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 푸시 구독 스키마 정의
const pushSubscriptionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  subscription: { type: Object, required: true },
  createdAt: { type: String, default: () => formatKoreanDate(new Date()) },
});

// 푸시 구독 모델 생성
const PushSubscription = mongoose.model(
  "PushSubscription",
  pushSubscriptionSchema
);

// 푸시 알림 API 라우트
// 푸시 알림 구독
app.post("/api/push/subscribe", auth, async (req, res) => {
  try {
    const subscription = req.body;
    const userId = req.user._id;

    // 이미 존재하는 구독인지 확인
    const existingSubscription = await PushSubscription.findOne({
      userId,
      "subscription.endpoint": subscription.endpoint,
    });

    if (existingSubscription) {
      return res.status(200).json({ message: "이미 구독 중입니다." });
    }

    // 새 구독 저장
    const newSubscription = new PushSubscription({
      userId,
      subscription,
    });

    await newSubscription.save();

    // 구독 확인 알림 전송
    const payload = JSON.stringify({
      title: "수행평가 알리미",
      body: "알림 구독이 완료되었습니다.",
      icon: "/icons/android-chrome-192x192.png",
      url: "/alerts.html",
    });

    await webpush.sendNotification(subscription, payload);

    res.status(201).json({ message: "구독이 완료되었습니다." });
  } catch (error) {
    console.error("푸시 알림 구독 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 푸시 알림 구독 취소
app.delete("/api/push/unsubscribe", auth, async (req, res) => {
  try {
    const { endpoint } = req.body;
    const userId = req.user._id;

    await PushSubscription.findOneAndDelete({
      userId,
      "subscription.endpoint": endpoint,
    });

    res.json({ message: "구독이 취소되었습니다." });
  } catch (error) {
    console.error("푸시 알림 구독 취소 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// VAPID 공개 키 가져오기
app.get("/api/push/vapidPublicKey", (req, res) => {
  res.json({ vapidPublicKey: VAPID_PUBLIC_KEY });
});

// 알림 전송 함수
const sendNotification = async (user, title, body, url = "/alerts.html") => {
  try {
    // 사용자의 모든 구독 정보 가져오기
    const subscriptions = await PushSubscription.find({ userId: user._id });

    if (subscriptions.length === 0) {
      return;
    }

    const payload = JSON.stringify({
      title,
      body,
      icon: "/icons/android-chrome-192x192.png",
      url,
    });

    // 각 구독에 알림 전송
    const sendPromises = subscriptions.map(async (sub) => {
      try {
        await webpush.sendNotification(sub.subscription, payload);
      } catch (error) {
        console.error("알림 전송 실패:", error);
        // 만료된 구독인 경우 삭제
        if (error.statusCode === 404 || error.statusCode === 410) {
          await PushSubscription.findByIdAndDelete(sub._id);
        }
      }
    });

    await Promise.all(sendPromises);
  } catch (error) {
    console.error("알림 전송 오류:", error);
  }
};

// 매일 아침 9시에 당일 수행평가 알림 전송 (스케줄러)
const sendDailyAlerts = async () => {
  try {
    // 오늘 날짜 설정 (시작: 오늘 00:00:00, 종료: 오늘 23:59:59)
    const today = getKoreanTime();
    today.setHours(0, 0, 0, 0);
    const todayStr = formatKoreanDateOnly(today); // YYYY-MM-DD 형식

    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowStr = formatKoreanDateOnly(tomorrow); // YYYY-MM-DD 형식

    // 오늘 마감인 알림 찾기 (문자열 비교)
    const todayAlerts = await Alert.find({
      date: {
        $gte: todayStr,
        $lt: tomorrowStr,
      },
    });

    // 사용자별로 알림 그룹화
    const userAlerts = {};

    // 각 알림에 대해 해당 학교/학년/반의 사용자 찾기
    for (const alert of todayAlerts) {
      const users = await User.find({
        school: alert.school,
        grade: alert.grade,
        class: alert.class,
      });

      for (const user of users) {
        const userId = user._id.toString();
        if (!userAlerts[userId]) {
          userAlerts[userId] = {
            user,
            alerts: [],
          };
        }
        userAlerts[userId].alerts.push(alert);
      }
    }

    // 각 사용자에게 알림 전송
    for (const userId in userAlerts) {
      const { user, alerts } = userAlerts[userId];

      if (alerts.length > 0) {
        const alertCount = alerts.length;
        const title = "오늘의 수행평가 알림";
        const body = `오늘 마감인 수행평가가 ${alertCount}개 있습니다.`;

        await sendNotification(user, title, body);
      }
    }

    console.log("일일 알림 전송 완료");
  } catch (error) {
    console.error("일일 알림 전송 오류:", error);
  }
};

// 하루 전 알림 전송 함수
const sendDayBeforeAlerts = async () => {
  try {
    // 내일 날짜 설정
    const tomorrow = getKoreanTime();
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);
    const tomorrowStr = formatKoreanDateOnly(tomorrow); // YYYY-MM-DD 형식

    const dayAfterTomorrow = new Date(tomorrow);
    dayAfterTomorrow.setDate(dayAfterTomorrow.getDate() + 1);
    const dayAfterTomorrowStr = formatKoreanDateOnly(dayAfterTomorrow); // YYYY-MM-DD 형식

    // 내일 마감인 알림 찾기 (문자열 비교)
    const tomorrowAlerts = await Alert.find({
      date: {
        $gte: tomorrowStr,
        $lt: dayAfterTomorrowStr,
      },
    });

    // 사용자별로 알림 그룹화
    const userAlerts = {};

    // 각 알림에 대해 해당 학교/학년/반의 사용자 찾기
    for (const alert of tomorrowAlerts) {
      const users = await User.find({
        school: alert.school,
        grade: alert.grade,
        class: alert.class,
      });

      for (const user of users) {
        const userId = user._id.toString();
        if (!userAlerts[userId]) {
          userAlerts[userId] = {
            user,
            alerts: [],
          };
        }
        userAlerts[userId].alerts.push(alert);
      }
    }

    // 각 사용자에게 알림 전송
    for (const userId in userAlerts) {
      const { user, alerts } = userAlerts[userId];

      if (alerts.length > 0) {
        const alertCount = alerts.length;
        const title = "내일 마감 수행평가 알림";
        const body = `내일 마감인 수행평가가 ${alertCount}개 있습니다.`;

        await sendNotification(user, title, body);
      }
    }

    console.log("하루 전 알림 전송 완료");
  } catch (error) {
    console.error("하루 전 알림 전송 오류:", error);
  }
};

// 주간 요약 알림 전송 함수 (매주 월요일)
const sendWeeklySummary = async () => {
  try {
    // 오늘이 월요일인지 확인 (한국 시간 기준)
    const today = getKoreanTime();
    if (today.getDay() !== 1) {
      // 1은 월요일
      return;
    }

    // 이번 주 시작과 끝 (월요일부터 일요일)
    const weekStart = new Date(today);
    weekStart.setHours(0, 0, 0, 0);
    const weekStartStr = formatKoreanDateOnly(weekStart); // YYYY-MM-DD 형식

    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 6); // 일요일
    weekEnd.setHours(23, 59, 59, 999);
    const weekEndStr = formatKoreanDateOnly(weekEnd) + " 23:59:59"; // YYYY-MM-DD 23:59:59 형식

    // 이번 주에 마감인 알림 찾기 (문자열 비교)
    const weeklyAlerts = await Alert.find({
      date: {
        $gte: weekStartStr,
        $lte: weekEndStr,
      },
    });

    // 사용자별로 알림 그룹화
    const userAlerts = {};

    // 각 알림에 대해 해당 학교/학년/반의 사용자 찾기
    for (const alert of weeklyAlerts) {
      const users = await User.find({
        school: alert.school,
        grade: alert.grade,
        class: alert.class,
        weeklySummary: true, // 주간 요약을 활성화한 사용자만 대상으로 함
      });

      for (const user of users) {
        const userId = user._id.toString();
        if (!userAlerts[userId]) {
          userAlerts[userId] = {
            user,
            alerts: [],
          };
        }
        userAlerts[userId].alerts.push(alert);
      }
    }

    // 각 사용자에게 알림 전송
    for (const userId in userAlerts) {
      const { user, alerts } = userAlerts[userId];

      if (alerts.length > 0) {
        const alertCount = alerts.length;
        const title = "이번 주 수행평가 요약";
        const body = `이번 주에 마감되는 수행평가가 ${alertCount}개 있습니다.`;

        await sendNotification(user, title, body);
      }
    }

    console.log("주간 요약 알림 전송 완료");
  } catch (error) {
    console.error("주간 요약 알림 전송 오류:", error);
  }
};

// 스케줄러 설정 (매일 아침 9시에 실행)
const setupSchedulers = () => {
  const runDailyTasks = () => {
    const now = getKoreanTime();
    console.log(`스케줄러 실행: ${formatKoreanDate(now)}`);

    // 매일 아침 9시에 당일 수행평가 알림
    sendDailyAlerts();

    // 하루 전 알림 (매일 실행)
    sendDayBeforeAlerts();

    // 주간 요약 (일요일에만 실행)
    sendWeeklySummary();
  };

  // 현재 시간 (한국 시간)
  const now = getKoreanTime();

  // 다음 실행 시간 계산 (오전 9시)
  const nextRun = new Date(now);
  nextRun.setHours(9, 0, 0, 0);

  // 이미 오전 9시가 지났으면 다음 날로 설정
  if (now >= nextRun) {
    nextRun.setDate(nextRun.getDate() + 1);
  }

  // 다음 실행까지 대기 시간 (밀리초)
  const timeUntilNextRun = nextRun - now;

  console.log(
    `다음 스케줄러 실행: ${formatKoreanDate(nextRun)} (${Math.floor(
      timeUntilNextRun / 60000
    )}분 후)`
  );

  // 첫 실행 예약
  setTimeout(() => {
    runDailyTasks();

    // 이후 매일 같은 시간에 실행
    setInterval(runDailyTasks, 24 * 60 * 60 * 1000);
  }, timeUntilNextRun);
};

// 서버 시작 시 스케줄러 설정
app.listen(PORT, () => {
  console.log(`서버가 포트 ${PORT}에서 실행 중입니다.`);
  setupSchedulers();
});
