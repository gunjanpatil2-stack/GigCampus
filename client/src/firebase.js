import { initializeApp, getApps, getApp } from 'firebase/app'
import { getAuth, GoogleAuthProvider, signInWithPopup } from 'firebase/auth'

// ─── All values come from .env (VITE_ prefix exposes them to the browser bundle)
// Never hardcode real API keys here — keep .env in .gitignore ─────────────────
const firebaseConfig = {
  apiKey:            import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain:        import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId:         import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket:     import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId:             import.meta.env.VITE_FIREBASE_APP_ID,
}

const isConfigured = Boolean(
  firebaseConfig.apiKey &&
  !firebaseConfig.apiKey.includes('Placeholder') &&
  firebaseConfig.projectId
)

// Initialize Firebase only when properly configured (singleton)
const app = isConfigured
  ? (getApps().length > 0 ? getApp() : initializeApp(firebaseConfig))
  : null

export const auth          = app ? getAuth(app) : null
export const googleProvider = app ? new GoogleAuthProvider() : null
if (googleProvider) googleProvider.setCustomParameters({ prompt: 'select_account' })

export const signInWithGoogle = async () => {
  if (!isConfigured || !app) {
    // Demo / dev fallback — clearly flagged, never silently used in prod
    if (import.meta.env.PROD) throw new Error('Firebase is not configured. Set VITE_FIREBASE_* env vars.')
    console.warn('[GigCampus] Firebase not configured — using mock Google sign-in for local dev only')
    return {
      email: 'google.student@gigcampus.test',
      name:  'Google Campus Student',
      photoURL: null,
      uid:   'google-mock-uid-dev'
    }
  }

  const result = await signInWithPopup(auth, googleProvider)
  const user   = result.user
  return {
    email:    user.email,
    name:     user.displayName || user.email.split('@')[0],
    photoURL: user.photoURL,
    uid:      user.uid,
  }
}
