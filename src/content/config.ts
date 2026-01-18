import { defineCollection, z } from 'astro:content';

const blogCollection = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.date(),
    category: z.string(),
    readTime: z.string(),
    author: z.string().optional(),
    type: z.enum(['research', 'blog']),
    tags: z.array(z.string()).optional(),
    draft: z.boolean().optional().default(false),
  }),
});

const certificationsCollection = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    issuer: z.string(),
    date: z.date(),
    credentialId: z.string().optional(),
    credentialUrl: z.string().optional(),
    certImage: z.string().optional(),
    description: z.string(),
    skills: z.array(z.string()).optional(),
    draft: z.boolean().optional().default(false),
  }),
});

const papersCollection = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.date(),
    category: z.string(),
    readTime: z.string(),
    authors: z.array(z.string()),
    tags: z.array(z.string()).optional(),
    pdfUrl: z.string().optional(),
    externalUrl: z.string().optional(),
    draft: z.boolean().optional().default(false),
  }),
});

export const collections = {
  blog: blogCollection,
  certifications: certificationsCollection,
  papers: papersCollection,
};
