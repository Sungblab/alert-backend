const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
require("dotenv").config();

// Express 앱 초기화
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

// 미들웨어 설정
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB 연결 설정
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/alert-project";
mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB에 연결되었습니다."))
  .catch((err) => console.error("MongoDB 연결 오류:", err));

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
    rejectUnauthorized: false // 인증서 검증 비활성화 (개발 환경용)
  },
  connectionTimeout: 10000, // 연결 타임아웃 10초
  greetingTimeout: 10000, // 인사 타임아웃 10초
  socketTimeout: 10000 // 소켓 타임아웃 10초
});

// 이메일 전송 테스트
transporter.verify(function(error, success) {
  if (error) {
    console.error('SMTP 서버 연결 오류:', error);
  } else {
    console.log('SMTP 서버가 준비되었습니다.');
  }
});

// 환경변수에 NEIS API 키 추가
const NEIS_API_KEY = process.env.NEIS_API_KEY;
const SCHOOL_CODE = "8490065";
const OFFICE_CODE = "Q10";

// 기본 라우트
app.get("/", (req, res) => {
  res.send("수행평가 알리미 API 서버가 실행 중입니다.");
});

// 사용자 스키마 정의
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  school: { type: String, required: true },
  grade: { type: String, required: true },
  class: { type: String, required: true },
  role: { type: String, default: "user", enum: ["user", "admin"] },
  isVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

// 이메일 인증 코드 스키마 정의
const verificationSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 600 } // 10분 후 자동 삭제
});

// 학교 스키마 정의
const schoolSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  address: { type: String },
  description: { type: String },
  createdAt: { type: Date, default: Date.now },
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
  date: { type: Date, required: true },
  description: { type: String, required: true },
  notify: { type: Boolean, default: false },
  school: { type: String, required: true },
  grade: { type: String, required: true },
  class: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  authorName: { type: String },
  isAnonymous: { type: Boolean, default: false }
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
  createdAt: { type: Date, default: Date.now },
  ipAddress: { type: String, required: true }
});

// 팁 댓글 스키마 정의
const tipCommentSchema = new mongoose.Schema({
  tipId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tip', required: true },
  content: { type: String, required: true },
  authorName: { type: String, default: "익명" },
  parentId: { type: mongoose.Schema.Types.ObjectId, ref: 'TipComment', default: null },
  createdAt: { type: Date, default: Date.now },
  ipAddress: { type: String, required: true }
});

const Tip = mongoose.model("Tip", tipSchema);
const TipComment = mongoose.model("TipComment", tipCommentSchema);

// 인증 미들웨어
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: '인증이 필요합니다.' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ message: '유효하지 않은 인증입니다.' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('인증 오류:', error);
    res.status(401).json({ message: '인증에 실패했습니다.' });
  }
};

// 관리자 인증 미들웨어
const adminAuth = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
      return res.status(401).json({ message: "인증이 필요합니다." });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.role !== "admin") {
      return res.status(403).json({ message: "관리자 권한이 필요합니다." });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("관리자 인증 오류:", error);
    res.status(401).json({ message: "인증에 실패했습니다." });
  }
};

// 이메일 인증 코드 생성 및 전송
app.post("/api/users/send-verification", async (req, res) => {
  try {
    const { email } = req.body;
    
    // 이메일 형식 검증
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "유효한 이메일 주소를 입력해주세요." });
    }
    
    // 이미 가입된 이메일인지 확인
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "이미 등록된 이메일입니다." });
    }
    
    // 6자리 인증 코드 생성
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // 이전 인증 코드 삭제
    await Verification.deleteMany({ email });
    
    // 새 인증 코드 저장
    const verification = new Verification({
      email,
      code: verificationCode
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
      `
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
      return res.status(400).json({ message: "인증 코드가 유효하지 않거나 만료되었습니다." });
    }
    
    // 인증 성공
    await Verification.deleteOne({ email, code });
    
    res.json({ verified: true, message: "이메일 인증이 완료되었습니다." });
  } catch (error) {
    console.error("이메일 인증 확인 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 회원가입
app.post("/api/users/register", async (req, res) => {
  try {
    const { name, email, password, school, grade, class: className, isVerified } = req.body;
    
    // 이메일 중복 확인
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "이미 등록된 이메일입니다." });
    }
    
    // 이메일 인증 확인
    if (!isVerified) {
      return res.status(400).json({ message: "이메일 인증이 필요합니다." });
    }
    
    // 비밀번호 해싱
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // 새 사용자 생성
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      school,
      grade,
      class: className,
      isVerified: true
    });
    
    await newUser.save();
    
    // JWT 토큰 생성
    const token = jwt.sign({ id: newUser._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.status(201).json({
      token,
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        school: newUser.school,
        grade: newUser.grade,
        class: newUser.class
      }
    });
  } catch (error) {
    console.error("회원가입 오류:", error);
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
      return res.status(400).json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
    }
    
    // 비밀번호 확인
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
    }
    
    // JWT 토큰 생성
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        school: user.school,
        grade: user.grade,
        class: user.class
      }
    });
  } catch (error) {
    console.error("로그인 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 현재 사용자 정보 가져오기
app.get("/api/users/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (error) {
    console.error("사용자 정보 조회 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 사용자 계정 정보 업데이트 (이메일, 비밀번호)
app.put("/api/users/account", auth, async (req, res) => {
  try {
    const { email, password, school, grade, class: className } = req.body;
    const user = req.user;

    console.log('계정 정보 업데이트 요청:', { email, school, grade, class: className });

    // 이메일 변경 시 중복 확인
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "이미 사용 중인 이메일입니다." });
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

    await user.save();

    // 비밀번호 제외하고 응답
    const userResponse = user.toObject();
    delete userResponse.password;

    console.log('업데이트된 사용자 정보:', userResponse);

    res.json({
      message: "계정 정보가 업데이트되었습니다.",
      user: userResponse
    });
  } catch (error) {
    console.error("계정 정보 업데이트 오류:", error);
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
    } = req.body;

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
      "느긋한 나무늘보"
    ];
    const randomName = anonymousNames[Math.floor(Math.random() * anonymousNames.length)];

    const newAlert = new Alert({
      title,
      date,
      description,
      notify,
      school,
      grade,
      class: className,
      authorName: randomName,
      isAnonymous: true
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
    const { title, date, description, notify, school, grade, class: className } = req.body;

    // 알림 존재 여부 확인
    const alert = await Alert.findById(id);
    if (!alert) {
      return res.status(404).json({ message: "알림을 찾을 수 없습니다." });
    }

    const updatedAlert = await Alert.findByIdAndUpdate(
      id,
      { title, date, description, notify, school, grade, class: className },
      { new: true }
    );

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
    const existingSchool = await School.findOne({ name, _id: { $ne: req.params.id } });
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
        return res.status(400).json({ message: "이미 사용 중인 이메일입니다." });
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
    const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || "admin_secret_key_123";
    if (secretKey !== ADMIN_SECRET_KEY) {
      return res.status(403).json({ message: "관리자 설정 키가 올바르지 않습니다." });
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
    const { school, grade, class: className, limit } = req.query;

    // 필터 조건 구성
    const filter = {};
    if (school) filter.school = school;
    if (grade) filter.grade = grade;
    if (className) filter.class = className;

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
        const comments = await TipComment.find({ tipId: tip._id }).sort({ createdAt: 1 });
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
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

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
      "느긋한 나무늘보"
    ];
    const randomName = authorName || anonymousNames[Math.floor(Math.random() * anonymousNames.length)];

    const newTip = new Tip({
      content,
      school,
      grade,
      class: className,
      authorName: randomName,
      ipAddress
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
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    const tip = await Tip.findById(id);
    if (!tip) {
      return res.status(404).json({ message: "팁을 찾을 수 없습니다." });
    }
    
    // IP 주소 확인 - 자신이 작성한 팁만 삭제 가능
    if (tip.ipAddress !== ipAddress) {
      return res.status(403).json({ message: "자신이 작성한 팁만 삭제할 수 있습니다." });
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
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
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
        return res.status(404).json({ message: "부모 댓글을 찾을 수 없습니다." });
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
      "느긋한 나무늘보"
    ];
    const randomName = authorName || anonymousNames[Math.floor(Math.random() * anonymousNames.length)];
    
    const newComment = new TipComment({
      tipId,
      content,
      authorName: randomName,
      parentId: parentId || null,
      ipAddress
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
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    const comment = await TipComment.findById(id);
    if (!comment) {
      return res.status(404).json({ message: "댓글을 찾을 수 없습니다." });
    }
    
    // IP 주소 확인 - 자신이 작성한 댓글만 삭제 가능
    if (comment.ipAddress !== ipAddress) {
      return res.status(403).json({ message: "자신이 작성한 댓글만 삭제할 수 있습니다." });
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
      return res.status(400).json({ message: "유효한 이메일 주소를 입력해주세요." });
    }
    
    // 사용자 확인
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "등록되지 않은 이메일입니다." });
    }
    
    // 6자리 인증 코드 생성
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // 이전 인증 코드 삭제
    await Verification.deleteMany({ email });
    
    // 새 인증 코드 저장
    const verification = new Verification({
      email,
      code: verificationCode
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
      `
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
      return res.status(400).json({ message: "인증 코드가 유효하지 않거나 만료되었습니다." });
    }
    
    // 사용자 확인
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }
    
    // 비밀번호 복잡성 검증
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ message: "비밀번호는 8자 이상이며, 영문, 숫자, 특수문자를 포함해야 합니다." });
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

// 서버 시작
app.listen(PORT, () => {
  console.log(`서버가 포트 ${PORT}에서 실행 중입니다.`);
});
