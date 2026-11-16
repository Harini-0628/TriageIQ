import axios, { type AxiosError, type InternalAxiosRequestConfig } from "axios";

// Known tradeoff, stated honestly: tokens live in localStorage here for
// simplicity. localStorage is readable by any JS on the page, so it's
// vulnerable to XSS token theft in a way an httpOnly cookie is not. A
// production version should issue the refresh token as an httpOnly,
// Secure, SameSite cookie and keep only the short-lived access token in
// memory. Worth naming exactly this if asked "how would you harden this."
const ACCESS_TOKEN_KEY = "triageiq_access_token";
const REFRESH_TOKEN_KEY = "triageiq_refresh_token";

export const tokenStorage = {
  getAccess: () => localStorage.getItem(ACCESS_TOKEN_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_TOKEN_KEY),
  set: (access: string, refresh: string) => {
    localStorage.setItem(ACCESS_TOKEN_KEY, access);
    localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
  },
  clear: () => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  },
};

export const api = axios.create({
  baseURL: "/api/v1",
});

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = tokenStorage.getAccess();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// A single in-flight refresh promise shared across every 401'd request
// that arrives at the same moment, so 5 simultaneous expired-token
// requests trigger ONE /auth/refresh call, not 5 racing ones.
let refreshPromise: Promise<string> | null = null;

async function refreshAccessToken(): Promise<string> {
  const refreshToken = tokenStorage.getRefresh();
  if (!refreshToken) throw new Error("No refresh token available");

  const response = await axios.post("/api/v1/auth/refresh", { refresh_token: refreshToken });
  const { access_token, refresh_token } = response.data;
  tokenStorage.set(access_token, refresh_token);
  return access_token;
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    if (error.response?.status === 401 && !originalRequest._retry && originalRequest.url !== "/auth/login") {
      originalRequest._retry = true;
      try {
        refreshPromise = refreshPromise ?? refreshAccessToken();
        const newAccessToken = await refreshPromise;
        refreshPromise = null;
        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        return api(originalRequest);
      } catch {
        refreshPromise = null;
        tokenStorage.clear();
        window.location.href = "/login";
      }
    }

    return Promise.reject(error);
  }
);
