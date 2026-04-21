import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";

export default function Register() {
  const { register, loading } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "" });

  const submit = async (e) => {
    e.preventDefault();
    try {
      await register(form.name, form.email, form.password);
      toast.success("Account created");
      navigate("/dashboard");
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Registration failed");
    }
  };

  return (
    <div className="min-h-screen grid md:grid-cols-2 bg-slate-950 text-white">
      <div className="hidden md:flex flex-col justify-between p-10 border-r border-slate-800 relative overflow-hidden">
        <div className="absolute inset-0 cyber-grid opacity-50" />
        <div className="relative">
          <div className="flex items-center gap-2 mb-8">
            <Shield className="h-5 w-5 text-cyan-400" />
            <span className="font-display font-bold">CyberShield</span>
          </div>
          <div className="max-w-md">
            <div className="text-[10px] uppercase tracking-[0.3em] text-cyan-400 mb-3">New operator</div>
            <h2 className="font-display text-3xl font-bold tracking-tight mb-3">
              Set up your threat-intel workspace.
            </h2>
            <p className="text-sm text-slate-400">
              Score profiles, track history, and surface stalker patterns in seconds.
            </p>
          </div>
        </div>
        <div className="relative text-[10px] uppercase tracking-[0.25em] text-slate-500">
          encrypted at rest · bcrypt
        </div>
      </div>

      <div className="flex items-center justify-center p-6 md:p-10">
        <form onSubmit={submit} className="w-full max-w-sm space-y-5" data-testid="register-form">
          <div>
            <h1 className="font-display text-2xl font-bold tracking-tight">Create account</h1>
            <p className="text-sm text-slate-400 mt-1">It takes 30 seconds.</p>
          </div>
          <div className="space-y-2">
            <Label className="text-xs text-slate-400 uppercase tracking-widest">Name</Label>
            <Input
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="bg-slate-950 border-slate-800 focus:border-cyan-500 font-mono-custom rounded-sm"
              data-testid="register-name-input"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs text-slate-400 uppercase tracking-widest">Email</Label>
            <Input
              type="email"
              required
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              className="bg-slate-950 border-slate-800 focus:border-cyan-500 font-mono-custom rounded-sm"
              data-testid="register-email-input"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs text-slate-400 uppercase tracking-widest">Password</Label>
            <Input
              type="password"
              required
              minLength={6}
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="bg-slate-950 border-slate-800 focus:border-cyan-500 font-mono-custom rounded-sm"
              data-testid="register-password-input"
            />
          </div>
          <Button
            type="submit"
            disabled={loading}
            className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-sm"
            data-testid="register-submit-btn"
          >
            {loading ? "Provisioning…" : "Create account"}
          </Button>
          <p className="text-xs text-slate-500 text-center">
            Already have access?{" "}
            <Link to="/login" className="text-cyan-400 hover:underline" data-testid="go-login-link">
              Sign in
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
