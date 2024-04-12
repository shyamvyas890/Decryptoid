import axios from "./AxiosWithCredentials.ts";
const hostname= "http://localhost:5001";
const axiosRequest = async (reqNum: 1 | 2 | 3 | 4, inputType: 1 | 2, pathname: string, theInput: Record<any,any>)=>{ // reqNum = POST =1 DELETE = 2 GET = 3 PUT = 4   inputType = Body= 1 Query = 2 (doesnt cover params input)     
    let response;
    if(reqNum===1){
        if(inputType === 1){
            response = await axios.post(`${hostname}/${pathname}`, theInput);
        }
        else if (inputType === 2){
            response = await axios.post(`${hostname}/${pathname}`, {params:theInput})
        }
    }
    else if(reqNum===2){
        if (inputType === 2){
            response= await axios.delete(`${hostname}/${pathname}`, {params:theInput})
        }
    }
    else if(reqNum===3){
        if (inputType === 2){
            response= await axios.get(`${hostname}/${pathname}`, {params:theInput})
        }
    }
    else if(reqNum===4){
        if(inputType === 1){
            response = await axios.put(`${hostname}/${pathname}`, theInput)
        }
    }
    return response;
}
export {axiosRequest, hostname};