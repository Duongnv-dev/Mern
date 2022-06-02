import React, { Fragment } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Navbar from './components/layout/Navbar';
import Landing from './components/layout/Landing';
import Register from './components/auth/Register';
import Login from './components/auth/Login';
import Alert from './components/layout/Alert'

//Redux
import { Provider } from 'react-redux';
import store from './store';

import './App.css';

const App =() => {
  return (
    <Provider store={store}>
    <BrowserRouter>
      <Navbar />
      <Alert />
      <section className="container">
        <Routes>
          <Route path='/' element={<Landing />}/>
          <Route path="/register" element={<Register />}/>
          <Route path="/login" element={<Login />}/>
        </Routes>
      </section>
    </BrowserRouter>
    </Provider>
  );
}

export default App;
