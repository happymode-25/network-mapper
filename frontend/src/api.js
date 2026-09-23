import axios from 'axios'

// Base URL comes from VITE_API_URL (defaults to /api, proxied by nginx in prod).
const baseURL = import.meta.env.VITE_API_URL || '/api'

export const api = axios.create({ baseURL })

export function apiErrorMessage(error, fallback = 'Something went wrong') {
  return error?.response?.data?.detail || error?.message || fallback
}