import { motion } from 'motion/react';
import { Link } from 'react-router-dom';
import { ShieldAlert, Zap, Database, Lock } from 'lucide-react';

export default function Landing() {
  return (
    <div className="max-w-4xl mx-auto py-12">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-20"
      >
        <h1 className="text-7xl font-bold tracking-tighter mb-6 leading-none">
          ADVANCED MALWARE <br />
          <span className="italic font-serif font-light">ANALYSIS PLATFORM</span>
        </h1>
        <p className="text-xl opacity-70 max-w-2xl mx-auto mb-10">
          Multi-layer threat detection using entropy analysis, signature matching, 
          and global intelligence feeds. Secure your perimeter with Sentinel.
        </p>
        <div className="flex justify-center gap-4">
          <Link to="/auth" className="bg-[#141414] text-[#E4E3E0] px-8 py-4 font-bold text-lg hover:scale-105 transition-transform">
            START_SCANNING
          </Link>
          <a href="#features" className="border border-[#141414] px-8 py-4 font-bold text-lg hover:bg-[#141414] hover:text-[#E4E3E0] transition-all">
            VIEW_SPECS
          </a>
        </div>
      </motion.div>

      <div id="features" className="grid md:grid-cols-2 gap-8 mb-20">
        {[
          { icon: ShieldAlert, title: "ENTROPY_ANALYSIS", desc: "Detect packed or encrypted malware by analyzing data randomness." },
          { icon: Zap, title: "SIGNATURE_SCANNING", desc: "Real-time pattern matching against known malware indicators." },
          { icon: Database, title: "THREAT_INTEL", desc: "Integration with VirusTotal and global reputation databases." },
          { icon: Lock, title: "SECURE_SANDBOX", desc: "Static analysis performed in an isolated, secure environment." }
        ].map((f, i) => (
          <motion.div 
            key={i}
            initial={{ opacity: 0, x: i % 2 === 0 ? -20 : 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="border border-[#141414] p-8 hover:bg-[#141414] hover:text-[#E4E3E0] transition-colors group"
          >
            <f.icon className="w-10 h-10 mb-4 group-hover:scale-110 transition-transform" />
            <h3 className="font-mono font-bold text-xl mb-2">{f.title}</h3>
            <p className="opacity-70 group-hover:opacity-100">{f.desc}</p>
          </motion.div>
        ))}
      </div>

      <div className="border-t border-[#141414] pt-8 flex justify-between items-center font-mono text-xs opacity-50">
        <span>© 2024 SENTINEL_CYBER_DEFENSE</span>
        <span>ENCRYPTED_CONNECTION_ESTABLISHED</span>
      </div>
    </div>
  );
}
