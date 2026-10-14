with Security_Policy;

procedure Policy_Smoke_Test is
   use Security_Policy;

   Context : Request_Context;
   Actual  : Decision_Kind;
   Expected : Decision_Kind;
begin
   -- Exhaustively exercise all 2**7 input combinations for every action.
   -- This is a runtime truth-table test, not a substitute for GNATprove.
   for Authenticated in Boolean loop
      for Replay_Free in Boolean loop
         for Input_Validated in Boolean loop
            for Signature_Valid in Boolean loop
               for Version_Acceptable in Boolean loop
                  for Consent in Boolean loop
                     for Hardware_Allowed in Boolean loop
                        Context :=
                          (Authenticated             => Authenticated,
                           Replay_Free               => Replay_Free,
                           Input_Validated           => Input_Validated,
                           Update_Signature_Valid    => Signature_Valid,
                           Update_Version_Acceptable => Version_Acceptable,
                           User_Consent              => Consent,
                           Hardware_Policy_Allowed   => Hardware_Allowed);

                        for Action in Action_Kind loop
                           Expected := Deny;
                           if Authenticated and Replay_Free and Input_Validated then
                              case Action is
                                 when Scan_Files =>
                                    Expected := Allow;
                                 when Update_Intelligence =>
                                    if Signature_Valid and Version_Acceptable then
                                       Expected := Allow;
                                    end if;
                                 when Quarantine_File =>
                                    if Consent then
                                       Expected := Allow;
                                    end if;
                                 when Hardware_Control =>
                                    if Hardware_Allowed then
                                       Expected := Allow;
                                    end if;
                              end case;
                           end if;

                           Actual := Evaluate (Action, Context);
                           pragma Assert (Actual = Expected);
                        end loop;
                     end loop;
                  end loop;
               end loop;
            end loop;
         end loop;
      end loop;
   end loop;
end Policy_Smoke_Test;
