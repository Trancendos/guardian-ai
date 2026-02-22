import { describe, expect, it } from "vitest";
import { GuardianAiService } from "./index";

describe("GuardianAiService", () => {
  it("reports active status", () => {
    const service = new GuardianAiService();
    expect(service.getStatus()).toEqual({
      name: "guardian-ai",
      status: "active",
    });
  });
});
