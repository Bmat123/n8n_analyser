import { Link, useLocation } from "react-router-dom";

export default function Nav() {
  const { pathname } = useLocation();

  const links = [
    { to: "/", label: "Analyze" },
    { to: "/rules", label: "Rules" },
  ];

  return (
    <nav className="border-b border-gray-800 bg-gray-900">
      <div className="container mx-auto px-4 max-w-6xl flex items-center gap-8 h-14">
        <span className="font-semibold text-white tracking-tight">
          n8n Analyzer
        </span>
        <div className="flex gap-4">
          {links.map(({ to, label }) => (
            <Link
              key={to}
              to={to}
              className={`text-sm transition-colors ${
                pathname === to
                  ? "text-white font-medium"
                  : "text-gray-400 hover:text-gray-200"
              }`}
            >
              {label}
            </Link>
          ))}
        </div>
      </div>
    </nav>
  );
}
