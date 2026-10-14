pragma SPARK_Mode (On);

package body Security_Policy is

   function Evaluate
     (Action  : Action_Kind;
      Context : Request_Context) return Decision_Kind
   is
   begin
      if not Context.Authenticated
        or else not Context.Replay_Free
        or else not Context.Input_Validated
      then
         return Deny;
      end if;

      case Action is
         when Scan_Files =>
            return Allow;

         when Update_Intelligence =>
            if Context.Update_Signature_Valid
              and then Context.Update_Version_Acceptable
            then
               return Allow;
            end if;
            return Deny;

         when Quarantine_File =>
            if Context.User_Consent then
               return Allow;
            end if;
            return Deny;

         when Hardware_Control =>
            if Context.Hardware_Policy_Allowed then
               return Allow;
            end if;
            return Deny;
      end case;
   end Evaluate;

end Security_Policy;
