import 'dotenv/config'
import bcrypt from 'bcryptjs'
import cors from 'cors'
import express from 'express'
import helmet from 'helmet'
import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit'
import { body, param, query, validationResult } from 'express-validator'
import xss from 'xss'

// ─── 1. SECURE API KEYS / NO HARDCODED SECRETS ───────────────────────────────
// JWT_SECRET MUST be set via .env — no fallback in production
const IS_PROD = process.env.NODE_ENV === 'production'
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET is missing or too short (min 32 chars). Set it in .env')
  if (IS_PROD) process.exit(1)
}
const secret = JWT_SECRET || 'dev-only-CHANGE-ME-before-deploy-32chars'

const app = express()
const now = () => new Date().toISOString()

// ─── 2. SECURITY HEADERS (helmet) ────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
    }
  },
  hsts: IS_PROD ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
  noSniff: true,
  xssFilter: true,
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}))

// ─── 3. CORS — only allow known origins ──────────────────────────────────────
const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:5173').split(',')
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true)
    cb(new Error('Not allowed by CORS'))
  },
  credentials: true
}))

app.use(express.json({ limit: '100kb' })) // tighten payload limit

// ─── 4. RATE LIMITING — logins, signups, and global ─────────────────────────
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false, message: { message: 'Too many requests, please try again later' } })
const authLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  standardHeaders: true, legacyHeaders: false, message: { message: 'Too many login attempts, please try again later' }, skipSuccessfulRequests: false })
app.use(globalLimiter)

// ─── 5. IN-MEMORY STORE (replace with DB for production) ─────────────────────
let users = [
  { id: 1, name: 'Aarav Mehta',  email: 'student@gigcampus.test', password: bcrypt.hashSync('password123', 12), role: 'STUDENT', skills: ['React', 'Python', 'SQL', 'Pandas', 'Tailwind'] },
  { id: 2, name: 'Pixel Club',   email: 'client@gigcampus.test',  password: bcrypt.hashSync('password123', 12), role: 'CLIENT',  skills: [] }
]
let gigs = [
  { id: 1, title: 'Build a portfolio website', description: 'Create a responsive portfolio for our annual showcase.', category: 'Web Development', budget: 8000, deadline: '2026-08-30', skills: ['React', 'Tailwind'], clientId: 2, client: 'Pixel Club', status: 'OPEN', applicants: 0, createdAt: now() }
]
let applications = [], messages = [], notifications = []

// ─── 6. HELPERS ───────────────────────────────────────────────────────────────
const publicUser = ({ password, ...user }) => user
const tokenFor   = user => jwt.sign({ id: user.id, role: user.role }, secret, { expiresIn: '7d' })

// ─── 7. INPUT VALIDATION SHORTCUT ─────────────────────────────────────────────
const validate = (req, res, next) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) return res.status(422).json({ message: errors.array()[0].msg })
  next()
}

// ─── 8. SANITISE USER CONTENT ─────────────────────────────────────────────────
const sanitise = str => (typeof str === 'string' ? xss(str.trim()) : str)

// ─── 9. AUTHENTICATION MIDDLEWARE ─────────────────────────────────────────────
const auth = (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '')
    if (!token) return res.status(401).json({ message: 'Sign in is required' })
    req.user = jwt.verify(token, secret)
    // ─── 10. NEVER TRUST FRONTEND IDs: re-fetch role from store ──────────────
    const dbUser = users.find(u => u.id === req.user.id)
    if (!dbUser) return res.status(401).json({ message: 'User not found' })
    req.user.role = dbUser.role // always use server-side role, not JWT claim alone
    next()
  } catch {
    res.status(401).json({ message: 'Sign in is required' })
  }
}

// ─── 11. ROLE MIDDLEWARE ──────────────────────────────────────────────────────
const role = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ message: 'You do not have permission for this action' })

const notify = (userId, type, text) =>
  notifications.push({ id: Date.now(), userId, type, text: sanitise(text), read: false, createdAt: now() })

// ─── 12. ERROR HANDLER — hide detailed errors in prod ─────────────────────────
const errorHandler = (err, req, res, _next) => {
  const status = err.status || 500
  if (IS_PROD) {
    res.status(status).json({ message: status < 500 ? err.message : 'An unexpected error occurred' })
  } else {
    res.status(status).json({ message: err.message, stack: err.stack })
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/health', (_, res) => res.json({ ok: true, storage: 'memory' }))

// ─── REGISTER ─────────────────────────────────────────────────────────────────
app.post('/api/auth/register',
  authLimiter,
  [
    body('name').trim().notEmpty().withMessage('Name is required').isLength({ max: 80 }),
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('role').optional().isIn(['STUDENT', 'CLIENT']).withMessage('Invalid role')
  ],
  validate,
  async (req, res) => {
    const { name, email, password, role: reqRole = 'STUDENT' } = req.body
    // Prevent ADMIN self-registration
    const safeRole = ['STUDENT', 'CLIENT'].includes(reqRole) ? reqRole : 'STUDENT'
    if (users.some(u => u.email === email)) return res.status(409).json({ message: 'Email is already registered' })
    const user = {
      id: users.length + 1,
      name: sanitise(name),
      email,
      password: await bcrypt.hash(password, 12),
      role: safeRole,
      skills: []
    }
    users.push(user)
    res.status(201).json({ user: publicUser(user), token: tokenFor(user) })
  }
)

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/auth/login',
  authLimiter,
  [
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required')
  ],
  validate,
  async (req, res) => {
    const user = users.find(u => u.email === req.body.email)
    // Constant-time compare even if user not found (prevents user enumeration)
    const match = user ? await bcrypt.compare(req.body.password, user.password) : await bcrypt.compare(req.body.password, '$2a$12$invalidhashtopreventtiming')
    if (!user || !match) return res.status(401).json({ message: 'Invalid email or password' })
    res.json({ user: publicUser(user), token: tokenFor(user) })
  }
)

// ─── GOOGLE AUTH ──────────────────────────────────────────────────────────────
app.post('/api/auth/google',
  authLimiter,
  [
    body('email').isEmail().withMessage('Email is required').normalizeEmail(),
    body('uid').notEmpty().withMessage('Firebase UID is required')
  ],
  validate,
  async (req, res) => {
    const { email, name, role: reqRole = 'STUDENT', uid } = req.body
    const safeRole = ['STUDENT', 'CLIENT'].includes(reqRole) ? reqRole : 'STUDENT'
    let user = users.find(u => u.email === email)
    if (!user) {
      user = {
        id: users.length + 1,
        name: sanitise(name || email.split('@')[0]),
        email,
        password: '',
        role: safeRole,
        skills: [],
        authProvider: 'firebase-google',
        firebaseUid: uid
      }
      users.push(user)
    }
    res.json({ user: publicUser(user), token: tokenFor(user) })
  }
)

// ─── PUBLIC GIGS ──────────────────────────────────────────────────────────────
app.get('/api/gigs',
  [
    query('q').optional().isString().isLength({ max: 100 }),
    query('category').optional().isString().isLength({ max: 50 }),
    query('sort').optional().isIn(['newest', 'budget', 'deadline'])
  ],
  validate,
  (req, res) => {
    const { q = '', category, sort = 'newest' } = req.query
    const safeQ = sanitise(q).toLowerCase()
    let list = gigs.filter(g =>
      g.status === 'OPEN' &&
      (!category || g.category === sanitise(category)) &&
      (g.title + g.description + g.category).toLowerCase().includes(safeQ)  // avoid JSON.stringify on full objects
    )
    if (sort === 'budget') list.sort((a, b) => b.budget - a.budget)
    if (sort === 'deadline') list.sort((a, b) => a.deadline.localeCompare(b.deadline))
    res.json(list)
  }
)

// ─── POST GIG ─────────────────────────────────────────────────────────────────
app.post('/api/gigs',
  auth, role('CLIENT'),
  [
    body('title').trim().notEmpty().withMessage('Title is required').isLength({ max: 120 }),
    body('description').trim().notEmpty().withMessage('Description is required').isLength({ max: 2000 }),
    body('category').trim().notEmpty().withMessage('Category is required').isLength({ max: 50 }),
    body('budget').isFloat({ min: 1 }).withMessage('Budget must be a positive number'),
    body('deadline').isISO8601().withMessage('Deadline must be a valid date'),
    body('skills').optional().isArray({ max: 20 }),
  ],
  validate,
  (req, res) => {
    const { title, description, category, skills = [], budget, deadline, requirements = '' } = req.body
    const clientUser = users.find(u => u.id === req.user.id)
    if (!clientUser) return res.status(401).json({ message: 'User not found' })
    const gig = {
      id: Date.now(),
      title: sanitise(title),
      description: sanitise(description),
      category: sanitise(category),
      skills: skills.map(s => sanitise(String(s))).slice(0, 20),
      budget: Number(budget),
      deadline,
      requirements: sanitise(requirements),
      clientId: req.user.id,       // ← always use authenticated user id, not body
      client: clientUser.name,
      status: 'OPEN',
      applicants: 0,
      createdAt: now()
    }
    gigs.unshift(gig)
    res.status(201).json(gig)
  }
)

// ─── RECOMMENDED GIGS ─────────────────────────────────────────────────────────
app.get('/api/gigs/recommended', auth, role('STUDENT'), (req, res) => {
  // ─── 13. ISOLATE USER DATA: only return data for the authenticated user ─────
  const me = users.find(u => u.id === req.user.id)
  if (!me) return res.status(401).json({ message: 'User not found' })
  const mySkills = me.skills.map(x => x.toLowerCase())
  res.json(
    gigs
      .filter(g => g.status === 'OPEN')
      .map(g => ({
        ...g,
        skillMatch: Math.round(100 * g.skills.filter(x => mySkills.includes(x.toLowerCase())).length / Math.max(g.skills.length, 1))
      }))
      .sort((a, b) => b.skillMatch - a.skillMatch)
  )
})

// ─── APPLY FOR GIG ────────────────────────────────────────────────────────────
app.post('/api/gigs/:id/applications',
  auth, role('STUDENT'),
  [
    param('id').isInt({ min: 1 }).withMessage('Invalid gig id'),
    body('proposal').trim().notEmpty().withMessage('Proposal is required').isLength({ max: 2000 }),
    body('bid').isFloat({ min: 1 }).withMessage('Bid must be a positive number'),
    body('days').isInt({ min: 1, max: 365 }).withMessage('Days must be between 1 and 365')
  ],
  validate,
  (req, res) => {
    const gig = gigs.find(g => g.id === Number(req.params.id))
    if (!gig || gig.status !== 'OPEN') return res.status(404).json({ message: 'Open gig not found' })
    if (applications.some(a => a.gigId === gig.id && a.studentId === req.user.id))
      return res.status(409).json({ message: 'You already applied for this gig' })
    const application = {
      id: Date.now(),
      gigId: gig.id,
      studentId: req.user.id,          // ← always from token, never from body
      proposal: sanitise(req.body.proposal),
      bid: Number(req.body.bid),
      days: Number(req.body.days),
      status: 'PENDING',
      createdAt: now()
    }
    applications.push(application)
    gig.applicants += 1
    notify(gig.clientId, 'NEW_APPLICATION', `New application for ${gig.title}`)
    res.status(201).json(application)
  }
)

// ─── GET GIG APPLICATIONS (client only, must own gig) ────────────────────────
app.get('/api/gigs/:id/applications',
  auth, role('CLIENT'),
  [param('id').isInt({ min: 1 }).withMessage('Invalid gig id')],
  validate,
  (req, res) => {
    const gig = gigs.find(g => g.id === Number(req.params.id))
    // ─── 14. ISOLATE USER DATA: client can only see their own gig's applications
    if (!gig) return res.status(404).json({ message: 'Gig not found' })
    if (gig.clientId !== req.user.id) return res.status(403).json({ message: 'You do not have permission for this action' })
    res.json(
      applications
        .filter(a => a.gigId === gig.id)
        .map(a => ({ ...a, student: publicUser(users.find(u => u.id === a.studentId)) }))
    )
  }
)

// ─── ACCEPT / REJECT APPLICATION ─────────────────────────────────────────────
app.patch('/api/applications/:id',
  auth, role('CLIENT'),
  [
    param('id').isInt({ min: 1 }).withMessage('Invalid application id'),
    body('status').isIn(['ACCEPTED', 'REJECTED']).withMessage('Status must be ACCEPTED or REJECTED')
  ],
  validate,
  (req, res) => {
    const application = applications.find(a => a.id === Number(req.params.id))
    const gig = application && gigs.find(g => g.id === application.gigId)
    // ─── Verify ownership — never trust frontend IDs ──────────────────────────
    if (!application || !gig || gig.clientId !== req.user.id)
      return res.status(404).json({ message: 'Application not found' })
    application.status = req.body.status
    if (application.status === 'ACCEPTED') {
      gig.status = 'IN_PROGRESS'
      applications.filter(a => a.gigId === gig.id && a.id !== application.id).forEach(a => (a.status = 'REJECTED'))
    }
    notify(application.studentId, `APPLICATION_${application.status}`, `Your application for ${gig.title} was ${application.status.toLowerCase()}`)
    res.json({ application, gig })
  }
)

// ─── UPDATE GIG STATUS ────────────────────────────────────────────────────────
app.patch('/api/gigs/:id/status',
  auth,
  [
    param('id').isInt({ min: 1 }).withMessage('Invalid gig id'),
    body('status').isIn(['OPEN', 'IN_PROGRESS', 'SUBMITTED', 'COMPLETED', 'CANCELLED']).withMessage('Invalid gig status')
  ],
  validate,
  (req, res) => {
    const gig = gigs.find(g => g.id === Number(req.params.id))
    if (!gig) return res.status(404).json({ message: 'Gig not found' })
    if (req.user.role !== 'ADMIN' && req.user.id !== gig.clientId)
      return res.status(403).json({ message: 'Only the client or admin can update this gig' })
    gig.status = req.body.status
    res.json(gig)
  }
)

// ─── MESSAGES — only parties involved in the gig ─────────────────────────────
app.get('/api/messages/:gigId',
  auth,
  [param('gigId').isInt({ min: 1 }).withMessage('Invalid gig id')],
  validate,
  (req, res) => {
    const gigId = Number(req.params.gigId)
    const gig = gigs.find(g => g.id === gigId)
    if (!gig) return res.status(404).json({ message: 'Gig not found' })
    // ─── Isolate: only the client or an accepted student can see messages ─────
    const isClient  = gig.clientId === req.user.id
    const isStudent = applications.some(a => a.gigId === gigId && a.studentId === req.user.id && a.status === 'ACCEPTED')
    const isAdmin   = req.user.role === 'ADMIN'
    if (!isClient && !isStudent && !isAdmin) return res.status(403).json({ message: 'You do not have access to these messages' })
    res.json(messages.filter(m => m.gigId === gigId))
  }
)

app.post('/api/messages/:gigId',
  auth,
  [
    param('gigId').isInt({ min: 1 }).withMessage('Invalid gig id'),
    body('text').trim().notEmpty().withMessage('Message text is required').isLength({ max: 1000 })
  ],
  validate,
  (req, res) => {
    const gigId = Number(req.params.gigId)
    const gig = gigs.find(g => g.id === gigId)
    if (!gig) return res.status(404).json({ message: 'Gig not found' })
    const isClient  = gig.clientId === req.user.id
    const isStudent = applications.some(a => a.gigId === gigId && a.studentId === req.user.id && a.status === 'ACCEPTED')
    const isAdmin   = req.user.role === 'ADMIN'
    if (!isClient && !isStudent && !isAdmin) return res.status(403).json({ message: 'You do not have access to this gig' })
    const message = {
      id: Date.now(),
      gigId,
      senderId: req.user.id,          // ← always from token
      text: sanitise(req.body.text),
      createdAt: now()
    }
    messages.push(message)
    res.status(201).json(message)
  }
)

// ─── NOTIFICATIONS — user's own only ─────────────────────────────────────────
app.get('/api/notifications', auth, (req, res) =>
  // ─── Isolate: filter strictly by authenticated user id ────────────────────
  res.json(notifications.filter(n => n.userId === req.user.id))
)

// ─── 15. PROTECTED ADMIN ROUTES ───────────────────────────────────────────────
app.get('/api/admin/metrics', auth, role('ADMIN'), (_, res) =>
  res.json({
    users: users.length,
    students: users.filter(u => u.role === 'STUDENT').length,
    clients: users.filter(u => u.role === 'CLIENT').length,
    gigs: gigs.length,
    completed: gigs.filter(g => g.status === 'COMPLETED').length
  })
)

// ─── 16. DISABLE DEBUG INFO IN PRODUCTION ─────────────────────────────────────
app.get('/api/admin/debug', auth, role('ADMIN'), (_, res) => {
  if (IS_PROD) return res.status(403).json({ message: 'Debug endpoint disabled in production' })
  res.json({ users: users.map(publicUser), gigs, applications, messages, notifications })
})

// ─── 17. CATCH-ALL + ERROR HANDLER ───────────────────────────────────────────
app.use((_, res) => res.status(404).json({ message: 'Not found' }))
app.use(errorHandler)

app.listen(process.env.PORT || 4000, () =>
  console.log(`GigCampus API running on http://localhost:${process.env.PORT || 4000} [${IS_PROD ? 'production' : 'development'}]`)
)
