import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000/api";

export async function submitUrlForAssessment(url) {
  const { data } = await axios.post(`${API_BASE_URL}/assess`, { url });
  return data;
}

export async function lookupAssessment(url) {
  const { data } = await axios.get(`${API_BASE_URL}/assess/lookup`, {
    params: { url },
  });
  return data;
}
