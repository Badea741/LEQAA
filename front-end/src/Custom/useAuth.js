import { useStytch } from "@stytch/react"
import { useContext, useState } from "react"
import { useDispatch, useSelector } from "react-redux"
import { authContext } from "../helper/authContext"
import { post } from "../redux/authSlice"


export function ProvideAuth({ children }) {
    const auth = useProvideAuth();
    return <authContext.Provider value={auth}>{children}</authContext.Provider>;
}

export const useAuth = () => {
    return useContext(authContext)
}
function useProvideAuth(params) {
    const dispatch = useDispatch()

    function signin(payload) {
        dispatch(post('https://fakestoreapi.com/auth/login', payload))
        console.log(payload);
    }

    function signup(payload) {
        // let email = payload.email

        // stytchClient.passwords.create({
        //     email,
        //     password,
        //     session_duration_minutes: 60,
        // })
    }

    function logout() {
        localStorage.clear();
    }

    return { signin, signup, logout }
}