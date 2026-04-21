export const RiskGauge = ({ score = 0, classification = "Safe" }) => {
  const pct = Math.max(0, Math.min(100, score));
  const color =
    classification === "High Risk"
      ? "#f43f5e"
      : classification === "Medium Risk"
      ? "#fbbf24"
      : "#34d399";

  // SVG half-circle gauge
  const radius = 90;
  const circumference = Math.PI * radius;
  const dash = (pct / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center py-4" data-testid="risk-gauge">
      <svg viewBox="0 0 220 130" className="w-full max-w-[320px]">
        <defs>
          <linearGradient id="gaugeBg" x1="0" x2="1">
            <stop offset="0%" stopColor="#34d399" />
            <stop offset="50%" stopColor="#fbbf24" />
            <stop offset="100%" stopColor="#f43f5e" />
          </linearGradient>
        </defs>
        <path
          d="M 20 110 A 90 90 0 0 1 200 110"
          fill="none"
          stroke="#1e293b"
          strokeWidth="16"
          strokeLinecap="butt"
        />
        <path
          d="M 20 110 A 90 90 0 0 1 200 110"
          fill="none"
          stroke="url(#gaugeBg)"
          strokeWidth="16"
          strokeLinecap="butt"
          strokeDasharray={`${dash} ${circumference}`}
          style={{ transition: "stroke-dasharray 0.8s ease-out" }}
        />
        <text
          x="110"
          y="95"
          textAnchor="middle"
          className="font-display"
          fontSize="44"
          fontWeight="700"
          fill={color}
          data-testid="risk-score-value"
        >
          {pct}
        </text>
        <text x="110" y="118" textAnchor="middle" fontSize="11" fill="#64748b" letterSpacing="2">
          RISK / 100
        </text>
      </svg>
      <div
        className="mt-2 px-4 py-1.5 text-xs uppercase tracking-[0.25em] font-mono-custom border"
        style={{ color, borderColor: `${color}55`, background: `${color}10` }}
        data-testid="risk-classification"
      >
        {classification}
      </div>
    </div>
  );
};
