pragma SPARK_Mode (On);

package Security_Policy is
   type Action_Kind is
     (Scan_Files,
      Update_Intelligence,
      Quarantine_File,
      Hardware_Control);

   type Decision_Kind is (Deny, Allow);

   type Request_Context is record
      Authenticated             : Boolean;
      Replay_Free               : Boolean;
      Input_Validated           : Boolean;
      Update_Signature_Valid    : Boolean;
      Update_Version_Acceptable : Boolean;
      User_Consent              : Boolean;
      Hardware_Policy_Allowed   : Boolean;
   end record;

   function Evaluate
     (Action  : Action_Kind;
      Context : Request_Context) return Decision_Kind
   with
     Global  => null,
     Depends => (Evaluate'Result => (Action, Context)),
     Post    =>
       (if Evaluate'Result = Allow then
          Context.Authenticated
          and Context.Replay_Free
          and Context.Input_Validated
          and (if Action = Update_Intelligence then
                 Context.Update_Signature_Valid
                 and Context.Update_Version_Acceptable)
          and (if Action = Quarantine_File then Context.User_Consent)
          and (if Action = Hardware_Control then
                 Context.Hardware_Policy_Allowed));
end Security_Policy;
