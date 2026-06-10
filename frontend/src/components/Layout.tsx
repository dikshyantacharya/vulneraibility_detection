import React from "react";
import Sidebar from "./Sidebar";
import TopBar from "./TopBar";

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="app">
      <Sidebar />
      <div className="main">
        <TopBar />
        <div className="content">{children}</div>
      </div>
    </div>
  );
}
