import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "ARTEX",
  version: packageJson.version,
  copyright: `© ${currentYear}, KT.`,
  meta: {
    title: "工作台",
    description: "任务与数据工作台",
  },
};
