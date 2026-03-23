import * as z from "zod";
const Url = z.object({
  url: z.url(),
});
const validateUrl = (object) => {
  return Url.safeParseAsync(object);
};

export default validateUrl;
