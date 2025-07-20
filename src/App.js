import React from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Mainpage from "./pages/Mainpage";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import FindAccount from "./pages/Findaccount";

function App() {
  return (
    <>
      <BrowserRouter>
        <Navbar />
        <Routes>
          <Route path="/" element={<Mainpage />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/find" element={<FindAccount />} />
        </Routes>
      </BrowserRouter>
    </>
  );
}

export default App;
