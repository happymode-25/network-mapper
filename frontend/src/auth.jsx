import React, { createContext, useContext } from 'react'
import { Navigate } from 'react-router-dom'

const AuthContext = createContext({ loggedIn: false })

export function AuthProvider({ children }) {
  const loggedIn = Boolean(localStorage.getItem('nm_token'))
  return <AuthContext.Provider value={{ loggedIn }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  return useContext(AuthContext)
}

export function RequireAuth({ children }) {
  const { loggedIn } = useAuth()
  if (!loggedIn) return <Navigate to="/login" replace />
  return children
}