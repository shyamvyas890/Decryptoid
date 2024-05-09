import React from "react";
import axios from "../utils/AxiosWithCredentials.ts";
import { hostname } from "../utils/utils.ts";
import styles from './Home.module.css';
import 'bootstrap/dist/css/bootstrap.min.css'; // npm install bootstrap

const HomeComponent = ()=>{
    const [cipherNum, setCipherNum]= React.useState< 1 | 2 | 3 | 4 | null>(null); // 1 is substitution cipher, 2 is double transposition, 3 is Rc4, 4 is DES
    const [isFile, setIsFile] = React.useState<boolean | null>(null);
    const [encrypt, setEncrypt] = React.useState<boolean | null>(null);
    const [theCipher, setTheCipher] = React.useState<string | null>(null);
    const [responseData, setResponseData] = React.useState<any>(null);
    const handleChooseEncryptionMethod = (event)=>{
        if(event.target.value === "0"){
            setCipherNum(null);
        }
        else{
            const cipher: 1 | 2 | 3 |4= parseInt(event.target.value) as 1 | 2 | 3 | 4;
            setCipherNum(cipher);
        }
    }

    const handleChooseInputMethod = (event)=>{
        setIsFile(event.target.value==="0"? null: event.target.value === "1"? true: false)
    }
    const handleChooseEncryptOrDecrypt = (event)=>{
        setEncrypt(event.target.value==="0"? null: event.target.value === "1"? true: false);
    }
    const handleChooseCipher = (event)=>{
        setTheCipher(event.target.value==="Select"? null: event.target.value)
    }
    const restart = (event)=>{
        setCipherNum(null);
        setIsFile(null);
        setEncrypt(null);
        setTheCipher(null);
        setResponseData(null);
    }
    const handleOnSubmit = async (event)=>{
        event.preventDefault();
        console.log(event);
        const theData = new FormData();
        if(isFile){
            theData.append('file', event.target.elements.theInputFile.files[0])
        }
        else if(isFile===false){
            theData.append('file', event.target.elements.theInputText.value)
        }
        if(theCipher!==null){
            theData.append('cipher', theCipher)
        }
        if(encrypt !== null){
            theData.append("encrypt", encrypt.toString())
        }
        if(encrypt === false && cipherNum === 2){
            theData.append('numberOfCharactersInOriginalMessage', event.target.elements.numberOfCharactersInOriginalMessage.value)
        }
        if(cipherNum === 3) {
            theData.append('rc4key', event.target.elements.rc4key.value)
        }
        if(cipherNum === 4) {
            theData.append('desKey', event.target.elements.desKey.value)
        }
        if(cipherNum === 1){
            try{
                const response = await axios.post(`${hostname}/substitution`, theData, {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    }
                });
                setResponseData(response.data);
            }
            catch(error){
                setResponseData({error: "There is something wrong with your input. Please try again."})
            }
        }
        else if(cipherNum === 2) {
            try{
                const response = await axios.post(`${hostname}/doubleTransposition`, theData, {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    }
                });
                console.log(response.data)
                setResponseData(response.data);
            }
            catch(error){
                setResponseData({error: "There is something wrong with your input. Please try again."})
            }
        }
        // ADD RC4
        else if(cipherNum === 3) {
            try{
                const response = await axios.post(`${hostname}/RC4`, theData, {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    }
                });
                console.log(response.data);
                setResponseData(response.data);
            }
            catch(error){
                console.log(error)
                setResponseData({error: "There is something wrong with your input. Please try again."})
            }
        }

        else if(cipherNum === 4) {
            try{
                const response = await axios.post(`${hostname}/DES`, theData, {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    }
                });
                console.log(response.data);
            }
            catch(error){
                console.log(error)
            }
        }

    }
    
    return (
        <>
       <div className={styles.bodyBackground}>
        <h1 className={styles.title}>Decryptoid</h1>
        <div className={`container ${styles.container}`}>
        <div className="row justify-content-center">
        <div className="col-md-8">
        {cipherNum === null? (
          <form className={`${styles.form} mb-4`}>
          <label className={styles.label}>Which method do you want to encrypt or decrypt with?</label>
          <select onChange={handleChooseEncryptionMethod} value={cipherNum === null ? 0 : cipherNum} className="form-control">
            <option value={0}>Select...</option>
            <option value={1}>Simple Substitution</option>
            <option value={2}>Double Transposition</option>
            <option value={3}>RC4</option>
            <option value={4}>DES</option>
          </select>
        </form>
        ) : (
            <>
              {responseData === null && (
                <form onSubmit={handleOnSubmit} className={styles.form}>
                  {isFile === null && (
                    <div className="mb-3">
                      <label className={styles.label}>Do you want to encrypt or decrypt with file or text input?</label>
                      <select onChange={handleChooseInputMethod} value={isFile === null ? 0 : isFile === true ? 1 : 2} className="form-control">
                        <option value={0}>Select</option>
                        <option value={1}>File</option>
                        <option value={2}>Text</option>
                      </select>
                    </div>
                  )}
                {isFile === true && (
                  <>
                    <label className={styles.label}>Please Upload your file here. Only txt files will be accepted.</label>
                    <input type="file" name="theInputFile" className="form-control mb-3" />
                  </>
                )}

                {isFile!== null && (
                <>
                   <label className={styles.label}>Do you want to encrypt or decrypt?</label>
                   <select onChange={handleChooseEncryptOrDecrypt} value={encrypt === null ? 0 : encrypt === true ? 1 : 2} className="form-control mb-3">
                      <option value={0}>Select</option>
                      <option value={1}>Encrypt</option>
                      <option value={2}>Decrypt</option>
                    </select>
                </>
                )}
                
                {isFile === false && (
                <>
                    {encrypt === true && (
                    <>
                        <label className={styles.label}>Enter your plaintext</label>
                        <input name="theInputText" placeholder="Enter message here..." className="form-control mb-3" />
                    </>
                    )}
                </>
                )}
                {isFile === false && (
                <>
                    {encrypt === false && (
                    <>
                        <label className={styles.label}>Enter your ciphertext</label>
                        <input name="theInputText" placeholder="Enter message here..." className="form-control mb-3" />
                    </>
                    )}
                </>
                )}
                
                {isFile !== null && cipherNum === 1 && encrypt !== null && (
                  <>
                    <label className={styles.label}>Select the cipher you want to use</label>
                    <select onChange={handleChooseCipher} value={theCipher === null ? "Select" : theCipher} className="form-control mb-3">
                      <option value={"Select"}>Select</option>
                      <option value={"qwertyuiopasdfghjklzxcvbnm-->cjkqmoxwbdrinuvplzsehgytaf"}>{`qwertyuiopasdfghjklzxcvbnm-->cjkqmoxwbdrinuvplzsehgytaf`}</option>
                      <option value={`qwertyuiopasdfghjklzxcvbnm-->qazwsxedcrfvtgbyhnujmikolp`}>{`qwertyuiopasdfghjklzxcvbnm-->qazwsxedcrfvtgbyhnujmikolp`}</option>
                    </select>
                    <button className={`${styles.button} btn btn-primary`} type="submit">Submit</button>
                  </>
                )}

                {isFile!==null && cipherNum===2 && encrypt!==null && (<>
                    <label className={styles.label}>Select the cipher you want to use</label>
                    <select onChange = {handleChooseCipher} value={theCipher===null? "Select": theCipher} className="form-control mb-3">
                        <option value={"Select"}>Select</option>
                        <option value={"alternateConsecutive"}>Alternate Consecutive</option>
                    </select>
                    {encrypt===false && <label className={styles.label}>How many characters was in the original message?<input type="text" name="numberOfCharactersInOriginalMessage"/></label>}
                    <button className={`${styles.button} btn btn-primary`} type="submit">Submit</button>
                </>)}

                {isFile!==null && cipherNum===3 && encrypt!==null && (<> 
                    <label className={styles.label}>What key do you want to use? <input type="text" name="rc4key" placeholder="Enter key..."/></label>
                    <button className={`${styles.button} btn btn-primary`} type="submit">Submit</button>
                </>)}
                {isFile!==null && cipherNum===4 && encrypt!==null && (<>
                    <label className={styles.label}>What key do you want to use? <input type="text" name="desKey" placeholder="Enter key..."/></label>
                    <button className={`${styles.button} btn btn-primary`} type="submit">Submit</button>
                </>)}
                
                </form>
                )}
                {responseData !== null && !responseData.error && cipherNum === 1 && (
                <div className={styles.resultContainer}>
                    <label className={styles.label}>Content<div>{typeof responseData === "string" ? responseData : ""}</div></label>
                    <button onClick={restart} className="btn btn-secondary">Restart</button>
                </div>
                )}

                {responseData !== null && !responseData.error && cipherNum === 2 && encrypt === true && (
                <div className={styles.resultContainer}>
                    <label className={styles.label}>Content<div>{typeof responseData === "string" ? responseData : responseData.theEncryptedContent}</div></label>
                    <label className={styles.label}>Length<div>{responseData.length}</div></label>
                    <button onClick={restart} className="btn btn-secondary">Restart</button>
                </div>
                )}
            
                {responseData !== null && !responseData.error && cipherNum === 2 && encrypt === false && (
                    <div className={styles.resultContainer}>
                        <label className={styles.label}>Content
                        <div>{typeof responseData === "string" ? responseData : responseData.theEncryptedContent}</div>
                        </label>
                        <button onClick={restart} className="btn btn-secondary">Restart</button>
                    </div>
                )}
            
                {responseData !== null && !responseData.error && cipherNum === 3 && (
                    <div className={styles.resultContainer}>
                        <label className={styles.label}>Content
                        <div>{typeof responseData === "string" ? responseData : responseData.theEncryptedContent}</div>
                        </label>
                        <button onClick={restart} className="btn btn-secondary">Restart</button>
                    </div>
                )}
            
                {responseData !== null && responseData.error && (
                    <div className={styles.resultContainer}>
                        <div className={styles.errorMessage}>Something is Wrong With Your Input</div>
                        <button onClick={restart} className="btn btn-secondary">Restart</button>
                    </div>
                )}
            </>
        ) }
        </div>
        </div>
        </div>
        </div>
        </>
    )
}

export default HomeComponent;