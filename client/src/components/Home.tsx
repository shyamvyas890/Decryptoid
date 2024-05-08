import React from "react";
import axios from "../utils/AxiosWithCredentials.ts";
import { hostname } from "../utils/utils.ts";
const HomeComponent = ()=>{
    const [cipherNum, setCipherNum]= React.useState< 1 | 2 | 3 | 4 | null>(null); // 1 is substitution cipher, 2 is double transposition, 3 is Rc4, 4 is DES
    const [isFile, setIsFile] = React.useState<boolean | null>(null);
    const [encrypt, setEncrypt] = React.useState<boolean | null>(null);
    const [theCipher, setTheCipher] = React.useState<string | null>(null);
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
                console.log(response.data);
            }
            catch(error){
                console.log(error)
            }

        }
        else if(cipherNum === 2) {
            try{
                const response = await axios.post(`${hostname}/doubleTransposition`, theData, {
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
        // ADD RC4
        else if(cipherNum === 3) {
            try{
                const response = await axios.post(`${hostname}/RC4`, theData, {
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
        cipherNum === null? (
            <form>
                <label>Which method do you want to encrypt or decrypt with?</label>
                <select onChange={handleChooseEncryptionMethod} value={cipherNum===null? 0: cipherNum}>
                    <option value={0}>Select...</option>
                    <option value={1}>Simple Substitution</option>
                    <option value={2}>Double Transposition</option>
                    <option value={3}>RC4</option>
                    <option value={4}>DES</option>
                </select>
            </form>
        ): (
            <form onSubmit={handleOnSubmit}>
                {isFile === null && (<div>
                    <label>Do you want to encrypt or decrypt with file or text input?</label>
                    <select onChange={handleChooseInputMethod} value={isFile===null? 0: isFile===true? 1: 2}>
                        <option value={0}>Select</option>
                        <option value={1}>File</option>
                        <option value={2}>Text</option>
                    </select>
                </div>)}
                {isFile===true && <><label>Please Upload your file here. Only txt files will be accepted.</label><input type="file" name="theInputFile"/></>}
                {isFile===false && <input name="theInputText"/>}                
                {isFile!== null && (<>
                <label>Do you want to encrypt or decrypt?</label>
                <select onChange={handleChooseEncryptOrDecrypt} value={encrypt===null? 0: encrypt===true? 1:2}>
                    <option value={0}>Select</option>
                    <option value={1}>Encrypt</option>
                    <option value={2}>Decrypt</option>
                </select>
                </>)}
                {isFile!==null && cipherNum===1 && encrypt!==null && (<>
                    <label>Select the cipher you want to use</label>
                    <select onChange = {handleChooseCipher} value={theCipher===null? "Select": theCipher}>
                        <option value={"Select"}>Select</option>
                        <option value={"qwertyuiopasdfghjklzxcvbnm-->cjkqmoxwbdrinuvplzsehgytaf"}>{`qwertyuiopasdfghjklzxcvbnm-->cjkqmoxwbdrinuvplzsehgytaf`}</option>
                        <option value={`qwertyuiopasdfghjklzxcvbnm-->qazwsxedcrfvtgbyhnujmikolp`}>{`qwertyuiopasdfghjklzxcvbnm-->qazwsxedcrfvtgbyhnujmikolp`}</option>
                    </select>
                    <button type="submit">Submit</button>
                </>)}
                {isFile!==null && cipherNum===2 && encrypt!==null && (<>
                    <label>Select the cipher you want to use</label>
                    <select onChange = {handleChooseCipher} value={theCipher===null? "Select": theCipher}>
                        <option value={"Select"}>Select</option>
                        <option value={"alternateConsecutive"}>Alternate Consecutive</option>
                    </select>
                    {encrypt===false && <label>How many characters was in the original message?<input type="text" name="numberOfCharactersInOriginalMessage"/></label>}
                    <button type="submit">Submit</button>
                </>)}
                {isFile!==null && cipherNum===3 && encrypt!==null && (<> 
                    <label>What key do you want to use?<input type="text" name="rc4key"/></label>
                    <button type="submit">Submit</button>
                </>)}
                {isFile!==null && cipherNum===4 && encrypt!==null && (<>
                    <label>What key do you want to use?<input type="text" name="desKey"/></label>
                    <button type="submit">Submit</button>
                </>)}
            </form>

        )
    )

}

export default HomeComponent;