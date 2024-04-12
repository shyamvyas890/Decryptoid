import realAxios from "axios";
const axiosWithCredentials = realAxios.create({
    withCredentials:true
})
export default axiosWithCredentials;