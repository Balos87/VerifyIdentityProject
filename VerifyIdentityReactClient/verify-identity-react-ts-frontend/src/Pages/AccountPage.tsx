import QuizCard from "../components/QuizCard"

const AccountPage = () => {
  return (
    <>
    <main className="flex flex-col items-center justify-center h-screen">
      <h1 className="block text-3xl/10">Account Page</h1>
      <div className="flex sm:mx-auto sm:my-auto border border-gray-300 w-100 h-100 rounded-lg shadow-lg">
        <QuizCard/>
      </div>
    </main>
    </>
  )
}

export default AccountPage
