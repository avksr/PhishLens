import { cn } from "@/lib/utils";
import React, { useState, createContext, useContext } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Menu, X } from "lucide-react";

export interface Links {
  label: string;
  href?: string;
  icon: React.JSX.Element | React.ReactNode;
  onClick?: () => void;
  active?: boolean;
}

interface SidebarContextProps {
  open: boolean;
  setOpen: React.Dispatch<React.SetStateAction<boolean>>;
  animate: boolean;
}

const SidebarContext = createContext<SidebarContextProps | undefined>(
  undefined
);

export const useSidebar = () => {
  const context = useContext(SidebarContext);
  if (!context) {
    throw new Error("useSidebar must be used within a SidebarProvider");
  }
  return context;
};

export const SidebarProvider = ({
  children,
  open: openProp,
  setOpen: setOpenProp,
  animate = true,
}: {
  children: React.ReactNode;
  open?: boolean;
  setOpen?: React.Dispatch<React.SetStateAction<boolean>>;
  animate?: boolean;
}) => {
  const [openState, setOpenState] = useState(false);

  const open = openProp !== undefined ? openProp : openState;
  const setOpen = setOpenProp !== undefined ? setOpenProp : setOpenState;

  return (
    <SidebarContext.Provider value={{ open, setOpen, animate }}>
      {children}
    </SidebarContext.Provider>
  );
};

export const Sidebar = ({
  children,
  open,
  setOpen,
  animate,
}: {
  children: React.ReactNode;
  open?: boolean;
  setOpen?: React.Dispatch<React.SetStateAction<boolean>>;
  animate?: boolean;
}) => {
  return (
    <SidebarProvider open={open} setOpen={setOpen} animate={animate}>
      {children}
    </SidebarProvider>
  );
};

export const SidebarBody = (props: React.ComponentProps<typeof motion.div>) => {
  return (
    <>
      <DesktopSidebar {...props} />
      <MobileSidebar {...(props as React.ComponentProps<"div">)} />
    </>
  );
};

export const DesktopSidebar = ({
  className,
  children,
  ...props
}: React.ComponentProps<typeof motion.div>) => {
  const { open, setOpen, animate } = useSidebar();
  return (
    <motion.div
      className={cn(
        "h-screen sticky top-0 px-3.5 py-4 hidden md:flex md:flex-col bg-slate-900/80 backdrop-blur-md border-r border-slate-800 w-[280px] shrink-0 z-30",
        className
      )}
      animate={{
        width: animate ? (open ? "280px" : "68px") : "280px",
      }}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      {...props}
    >
      {children}
    </motion.div>
  );
};

export const MobileSidebar = ({
  className,
  children,
  ...props
}: React.ComponentProps<"div">) => {
  const { open, setOpen } = useSidebar();
  return (
    <div
      className={cn(
        "h-14 px-4 py-3 flex flex-row md:hidden items-center justify-between bg-slate-900/90 backdrop-blur-md border-b border-slate-800 w-full z-40 sticky top-0",
        className
      )}
      {...props}
    >
      <div className="flex items-center gap-2">
        <span className="text-xl" aria-hidden>🛡️</span>
        <span className="font-bold text-sm bg-gradient-to-r from-cyan-400 to-slate-200 bg-clip-text text-transparent">
          PhishLens
        </span>
      </div>
      <div className="flex justify-end z-20">
        <Menu
          className="text-slate-300 hover:text-cyan-400 cursor-pointer size-6 transition-colors"
          onClick={() => setOpen(!open)}
        />
      </div>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ x: "-100%", opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: "-100%", opacity: 0 }}
            transition={{
              duration: 0.3,
              ease: "easeInOut",
            }}
            className={cn(
              "fixed h-full w-full inset-0 bg-slate-950/95 backdrop-blur-xl p-8 z-[120] flex flex-col justify-between border-r border-slate-800",
              className
            )}
          >
            <div
              className="absolute right-6 top-6 z-50 text-slate-300 hover:text-cyan-400 cursor-pointer"
              onClick={() => setOpen(!open)}
            >
              <X className="size-6" />
            </div>
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export const SidebarLink = ({
  link,
  className,
  ...props
}: {
  link: Links;
  className?: string;
  props?: Record<string, unknown>;
}) => {
  const { open, animate } = useSidebar();
  return (
    <a
      href={link.href || "#"}
      onClick={(e) => {
        if (link.onClick) {
          e.preventDefault();
          link.onClick();
        }
      }}
      className={cn(
        "flex items-center justify-start gap-3 group/sidebar py-2.5 px-2.5 rounded-xl transition-all cursor-pointer font-sans",
        link.active
          ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-[0_0_12px_rgba(0,240,255,0.1)]"
          : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent",
        className
      )}
      {...props}
    >
      <div
        className={cn(
          "shrink-0 size-5 flex items-center justify-center transition-colors",
          link.active ? "text-cyan-400" : "text-slate-400 group-hover/sidebar:text-slate-200"
        )}
      >
        {link.icon}
      </div>

      <motion.span
        animate={{
          display: animate ? (open ? "inline-block" : "none") : "inline-block",
          opacity: animate ? (open ? 1 : 0) : 1,
        }}
        className="text-sm font-medium whitespace-pre inline-block !p-0 !m-0 transition duration-150"
      >
        {link.label}
      </motion.span>
    </a>
  );
};
