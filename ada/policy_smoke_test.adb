with Security_Policy;

procedure Policy_Smoke_Test is
   use Security_Policy;

   Base_Context : constant Request_Context :=
     (Authenticated             => True,
      Replay_Free               => True,
      Input_Validated           => True,
      Update_Signature_Valid    => True,
      Update_Version_Acceptable => True,
      User_Consent              => True,
      Hardware_Policy_Allowed   => True);

   Context : Request_Context;
begin
   Context := Base_Context;
   pragma Assert (Evaluate (Scan_Files, Context) = Allow);

   Context := Base_Context;
   Context.Authenticated := False;
   pragma Assert (Evaluate (Scan_Files, Context) = Deny);

   Context := Base_Context;
   Context.Replay_Free := False;
   pragma Assert (Evaluate (Scan_Files, Context) = Deny);

   Context := Base_Context;
   Context.Update_Signature_Valid := False;
   pragma Assert (Evaluate (Update_Intelligence, Context) = Deny);

   Context := Base_Context;
   Context.Update_Version_Acceptable := False;
   pragma Assert (Evaluate (Update_Intelligence, Context) = Deny);

   Context := Base_Context;
   Context.User_Consent := False;
   pragma Assert (Evaluate (Quarantine_File, Context) = Deny);

   Context := Base_Context;
   Context.Hardware_Policy_Allowed := False;
   pragma Assert (Evaluate (Hardware_Control, Context) = Deny);
end Policy_Smoke_Test;
