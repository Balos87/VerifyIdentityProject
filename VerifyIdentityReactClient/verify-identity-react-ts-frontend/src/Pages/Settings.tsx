

const Settings = () => {
  return (
    <main className="min-h-screen bg-gray-100 px-6 py-12">
      <div className="max-w-3xl mx-auto bg-white rounded-lg shadow-md p-8">
        <h1 className="text-3xl font-bold mb-6 text-gray-800">Settings</h1>

        <div className="space-y-8">
          {/* Profile Info */}
          <section>
            <h2 className="text-xl font-semibold text-gray-700 mb-2">Profile Information</h2>
            <div className="space-y-4">
              <div className="flex flex-col">
                <label className="text-sm text-gray-600 mb-1">Display Name</label>
                <input
                  type="text"
                  placeholder="Jane Doe"
                  className="px-4 py-2 border rounded-md w-full focus:outline-none focus:ring-2 focus:ring-cyan-600"
                />
              </div>
              <div className="flex flex-col">
                <label className="text-sm text-gray-600 mb-1">Email</label>
                <input
                  type="email"
                  placeholder="you@example.com"
                  className="px-4 py-2 border rounded-md w-full focus:outline-none focus:ring-2 focus:ring-cyan-600"
                />
              </div>
            </div>
          </section>

          {/* Preferences */}
          <section>
            <h2 className="text-xl font-semibold text-gray-700 mb-2">Preferences</h2>
            <div className="flex items-center gap-4">
              <label className="text-gray-700">Enable notifications</label>
              <input type="checkbox" className="w-5 h-5 text-cyan-600 focus:ring-cyan-500" />
            </div>
          </section>

          {/* Save Button */}
          <div className="pt-4">
            <button className="bg-cyan-600 hover:bg-cyan-700 text-white font-semibold px-6 py-2 rounded-md">
              Save Changes
            </button>
          </div>
        </div>
      </div>
    </main>
  )
}

export default Settings;

