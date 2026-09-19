import axios from 'axios'

// Base URL comes from VITE_API_URL (defaults to /api, proxied by nginx in prod).
const baseURL = import.meta.env.VITE_API_URL || '/api'

export const api = axios.create({ baseURL })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('nm_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('nm_token')
      if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export async function login(username, password) {
  const form = new URLSearchParams()
  form.append('username', username)
  form.append('password', password)
  const { data } = await axios.post(`${baseURL}/token`, form)
  localStorage.setItem('nm_token', data.access_token)
  return data
}

export function logout() {
  localStorage.removeItem('nm_token')
  window.location.href = '/login'
}

export function apiErrorMessage(error, fallback = 'Something went wrong') {
  return error?.response?.data?.detail || error?.message || fallback
}