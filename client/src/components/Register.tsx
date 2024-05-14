// RegistrationComponent.js
import React, { useState } from 'react';
import axios from '../utils/AxiosWithCredentials.ts';
import { Link, useNavigate } from 'react-router-dom';
import { hostname } from '../utils/utils.ts';
const RegistrationComponent = () => {
  const [feedback, setFeedback] = useState('');
  const navigate = useNavigate();
  function validateEmail(field){
    if (field === "") {
      return "No Email was entered.\n"
    }
    else if (!((field.indexOf(".") > 0) && (field.indexOf("@") > 0)) || /[^a-zA-Z0-9.@_-]/.test(field)) {
      return "The Email address is invalid.\n"
    }
    return ""
  }

  function validateUsername(field)
  {
    if (field === "") {
      return "No Username was entered.\n"
    }
    else if (/[^a-zA-Z0-9_-]/.test(field)) {
      return "Only a-z, A-Z, 0-9, - and _ allowed in Usernames.\n"
    }
    return ""
  }
  function validateEmailAndUsername(email, username){
    let fail = validateEmail(email);
    fail += validateUsername(username);
    return fail;
  }

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const emailAndUsernameValidity = validateEmailAndUsername(e.target.elements.emailInput.value, e.target.elements.usernameInput.value);
      if(emailAndUsernameValidity !== ""){
        window.alert(emailAndUsernameValidity);
        return;
      }
      try {
        await axios.post(`${hostname}/logout`);
      }
      catch(error){

      }
      const response = await axios.post(`${hostname}/register`, 
      {
        username:e.target.elements.usernameInput.value,
        password:e.target.elements.passwordInput.value,
        email: e.target.elements.emailInput.value
      }
      );
      console.log(response)
      e.target.elements.usernameInput.value="";
      e.target.elements.passwordInput.value="";
      e.target.elements.emailInput.value="";
      setFeedback(response.data);
      navigate("/login");
    } catch (error) {
        console.log(error);
        e.target.elements.usernameInput.value="";
        e.target.elements.passwordInput.value="";
        e.target.elements.emailInput.value="";
        setFeedback(error.response.data);
    }
  };


  return (
    <div>
      <h2>Registration</h2>
      <form onSubmit={handleRegister}>
        <label>
          Username:
          <br />
          <input type="text" name='usernameInput' />
        </label>
        <br />
        <label>
          Email
          <br />
          <input type="email" name="emailInput" />
        </label>
        <br />
        <label>
          Password:
          <br />
          <input type="password" name='passwordInput' />
        </label>
        <br />
        <button type="submit">Register</button>
      </form>
      <div>Already have an account? <Link to="/login">Login here!</Link></div>
      {feedback && (feedback!=="User Registered Successfully") && <p style={{color:'red'}}>{feedback}</p>}
      {feedback && feedback=== "User Registered Successfully" && <p style={{color:'green'}}>{feedback}</p>}
    </div>
  );
};

export default RegistrationComponent;