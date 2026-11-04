import type { MetadataRoute } from "next";

// 公网站点不参与任何搜索引擎索引：
//   · 这类控制台被收录后，等于把入口和页面标题直接交给扫描器（见 issue #61 A6）
//   · 全站 Disallow + 不提供 sitemap；再配合 layout 里的 robots meta 做双保险
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        disallow: "/",
      },
    ],
  };
}
