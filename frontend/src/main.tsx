import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { AppProvider, DashboardProvider } from "./state";
import "./styles/globals.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AppProvider>
        <DashboardProvider>
          <App />
        </DashboardProvider>
      </AppProvider>
    </BrowserRouter>
  </React.StrictMode>
);
