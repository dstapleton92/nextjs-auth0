import { SdkError } from "./sdk-error.js";

export class MissingKeyError extends SdkError {
  public code = "ERR_KID_NOT_FOUND";
}
