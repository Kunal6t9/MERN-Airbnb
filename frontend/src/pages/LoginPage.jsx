import { Link } from "react-router-dom"

export default function LoginPage() {
  return (
    <div className="mt-4 grow flex items-center justify-around">
      <div className="mb-64">
         <h1 className="text-4xl text-center mb-4">Login</h1>
      <form className="max-w-md mx-auto">
        <input type="email" placeholder="Enter Email"/>
        <input type="password" placeholder="Enter Password"/>
        <button className="primary">Login</button>
        <div className="text-center py-2 text-gray-500">
          Don't have an account ? <Link className="underline text-black" to={"/register"}>Register Now !</Link>
        </div>
      </form>
      </div>   
    </div>
  )
}